//
// upload.go
// Copyright(c)2014-2015 Google, Inc.
//
// This file is part of skicka.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"github.com/cheggaaa/pb"
	"github.com/google/skicka/gdrive"
	"google.golang.org/api/drive/v2"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type byteCountingReader struct {
	R         io.Reader
	bytesRead int64
}

func (bcr *byteCountingReader) Read(dst []byte) (int, error) {
	read, err := bcr.R.Read(dst)
	bcr.bytesRead += int64(read)
	return read, err
}

func uploadUsage() {
	fmt.Printf("Usage: skicka upload [-ignore-times] [-encrypt] local_path drive_path\n")
	fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
}

func upload(args []string) int {
	ignoreTimes := false
	encrypt := false

	if len(args) < 2 {
		uploadUsage()
		return 1
	}

	i := 0
	for ; i+2 < len(args); i++ {
		switch args[i] {
		case "-ignore-times":
			ignoreTimes = true
		case "-encrypt":
			encrypt = true
		default:
			uploadUsage()
			return 1
		}
	}
	trustTimes := !ignoreTimes

	localPath := filepath.Clean(args[i])
	drivePath := filepath.Clean(args[i+1])

	// Make sure localPath exists.
	if _, err := os.Stat(localPath); err != nil {
		printErrorAndExit(err)
	}

	recursive := true
	includeBase := true
	mustExist := false
	fmt.Fprintf(os.Stderr, "skicka: Getting list of files to upload... ")
	files, err := gd.GetFilesUnderPath(drivePath, recursive, includeBase,
		mustExist)
	fmt.Fprintf(os.Stderr, "Done.\n")
	if err != nil {
		printErrorAndExit(err)
	}

	syncStartTime = time.Now()
	errs := syncHierarchyUp(localPath, drivePath, files, encrypt,
		trustTimes)

	printFinalStats()
	return errs
}

// Representation of a local file that may need to be synced up to Drive.
type localToRemoteFileMapping struct {
	LocalPath     string
	RemotePath    string
	LocalFileInfo os.FileInfo
}

// Implement sort.Interface so that we can sort arrays of
// localToRemoteFileMapping by file size.
type localToRemoteBySize []localToRemoteFileMapping

func (l2r localToRemoteBySize) Len() int      { return len(l2r) }
func (l2r localToRemoteBySize) Swap(i, j int) { l2r[i], l2r[j] = l2r[j], l2r[i] }
func (l2r localToRemoteBySize) Less(i, j int) bool {
	return l2r[i].LocalFileInfo.Size() < l2r[j].LocalFileInfo.Size()
}

// Perform fairly inexpensive comparisons of the file size and last modification
// time metadata of the local file and the corresponding file on Google Drive.
// If these values match, we assume that the two files are consistent and don't
// examine the local file contents further to see if an upload is required
// (unless the -ignore-times flag has been used).
func fileMetadataMatches(info os.FileInfo, encrypt bool,
	driveFile *drive.File) (bool, bool, error) {
	// Compare file sizes.
	localSize := info.Size()
	driveSize := driveFile.FileSize
	if encrypt {
		// We store a copy of the initialization vector at the start of
		// the file stored in Google Drive; account for this when
		// comparing the file sizes.
		driveSize -= aes.BlockSize
	}
	sizeMatches := localSize == driveSize

	// Compare modification times.
	driveTime, err := gdrive.GetModificationTime(driveFile)
	if err != nil {
		return sizeMatches, false, err
	}
	localTime := info.ModTime()
	debug.Printf("localTime: %v, driveTime: %v", localTime, driveTime)
	return sizeMatches, localTime.Equal(driveTime), nil
}

// Given a file on the local disk, synchronize it with Google Drive: if the
// corresponding file doesn't exist on Drive, it's created; if it exists
// but has different contents, the contents are updated.  The Unix
// permissions and file modification time on Drive are also updated
// appropriately.
func syncFileUp(fileMapping localToRemoteFileMapping, encrypt bool,
	files gdrive.Files, pb *pb.ProgressBar) error {
	// We need to create the file or folder on Google Drive.
	debug.Printf("syncFileUp: %#v", fileMapping.LocalFileInfo)

	// Get the *drive.File for the folder to create the new file in.
	// This folder should definitely exist at this point, since we
	// create all folders needed before starting to upload files.
	dirPath := filepath.Dir(fileMapping.RemotePath)
	if dirPath == "." {
		dirPath = "/"
	}
	parentFolder, err := files.GetOne(dirPath)
	checkFatalError(err, "get parent directory")

	baseName := filepath.Base(fileMapping.RemotePath)
	var driveFile *drive.File

	if fileMapping.LocalFileInfo.IsDir() {
		driveFile, err = createDriveFolder(baseName,
			fileMapping.LocalFileInfo.Mode(), fileMapping.LocalFileInfo.ModTime(),
			parentFolder)
		if err != nil {
			return err
		}
		atomic.AddInt64(&stats.UploadBytes, fileMapping.LocalFileInfo.Size())
		pb.Increment()
		verbose.Printf("Created Google Drive folder %s", fileMapping.RemotePath)

		// We actually only update the map when we create new folders;
		// we don't update it for new files.  There are two reasons
		// for this: first, once we've created a file, we don't
		// access it again during a given run of skicka.
		// Second, file upload is multi-threaded, and would require a
		// mutex to the map, which doesn't seem worth the trouble
		// given the first reason.
		//
		// Note that if the contents of Google Drive are modified in
		// another session, this map may become stale; we don't
		// explicitly look out for this and will presumably error out
		// in interesting ways if it does happen.
		files.Add(fileMapping.RemotePath, driveFile)
	} else {
		if driveFile, err = files.GetOne(fileMapping.RemotePath); err == gdrive.ErrNotExist {
			driveFile, err = createDriveFile(baseName, fileMapping.LocalFileInfo.Mode(),
				fileMapping.LocalFileInfo.ModTime(), encrypt, parentFolder)
			if err != nil {
				return err
			}
		}

		var iv []byte
		if encrypt {
			iv, err = getInitializationVector(driveFile)
			if err != nil {
				return fmt.Errorf("unable to get IV: %v", err)
			}
		}

		err = uploadFileContents(fileMapping.LocalPath, driveFile, encrypt, iv, pb)
		if err != nil {
			return err
		}
	}

	verbose.Printf("Updated local %s -> Google Drive %s", fileMapping.LocalPath,
		fileMapping.RemotePath)
	return gd.UpdateModificationTime(driveFile, fileMapping.LocalFileInfo.ModTime())
}

// uploadFileContents does its best to upload the local file stored at
// localPath to the given *drive.File on Google Drive.  (It assumes that
// the *drive.File has already been created.)
func uploadFileContents(localPath string, driveFile *drive.File, encrypt bool, iv []byte,
	pb *pb.ProgressBar) error {
	for ntries := 0; ntries < 5; ntries++ {
		var reader io.Reader
		var countingReader *byteCountingReader

		contentsReader, length, err :=
			getFileContentsReaderForUpload(localPath, encrypt, iv)
		if contentsReader != nil {
			defer contentsReader.Close()
		}
		if err != nil {
			return err
		}
		reader = contentsReader

		if pb != nil {
			countingReader = &byteCountingReader{
				R: reader,
			}
			reader = io.TeeReader(countingReader, pb)
		}

		if length >= resumableUploadMinSize {
			err = gd.UploadFileContentsResumable(driveFile, reader, length)
		} else {
			err = gd.UploadFileContents(driveFile, reader, length, ntries)
		}

		if err == nil {
			// Success!
			atomic.AddInt64(&stats.DriveFilesUpdated, 1)
			atomic.AddInt64(&stats.UploadBytes, length)
			return nil
		}

		if re, ok := err.(gdrive.RetryHTTPTransmitError); ok {
			debug.Printf("%s: got retry http error--retrying: %s",
				localPath, re.Error())
			if pb != nil {
				// The "progress" made so far on this file should be
				// rolled back
				pb.Add64(-countingReader.bytesRead)
			}
		} else {
			debug.Printf("%s: giving up due to error: %v", localPath, err)
			// This file won't be uploaded, so subtract the expected
			// progress from the total expected bytes
			if pb != nil {
				pb.Add64(-countingReader.bytesRead)
				pb.Total -= length
			}
			return err
		}
	}
	return nil
}

// Synchronize a local directory hierarchy with Google Drive.
// localPath is the file or directory to start with, driveRoot is
// the directory into which the file/directory will be sent
func syncHierarchyUp(localPath string, driveRoot string,
	existingFiles gdrive.Files, encrypt bool, trustTimes bool) int {
	if encrypt && key == nil {
		key = decryptEncryptionKey()
	}

	fileMappings, err := compileUploadFileTree(localPath, driveRoot, encrypt)
	checkFatalError(err, "error getting local filetree")
	fileMappings, err = filterFilesToUpload(fileMappings, existingFiles, encrypt,
		trustTimes)
	checkFatalError(err, "error determining files to sync")

	if len(fileMappings) == 0 {
		fmt.Fprintln(os.Stderr, "skicka: No files to be uploaded.")
		return 0
	}

	nBytesToUpload := int64(0)
	for _, info := range fileMappings {
		if !info.LocalFileInfo.IsDir() {
			nBytesToUpload += info.LocalFileInfo.Size()
		}
	}

	// Given the list of files to sync, first find all of the directories and
	// then either get or create a Drive folder for each one.
	directoryMappingMap := make(map[string]localToRemoteFileMapping)
	var directoryNames []string
	for _, localfile := range fileMappings {
		if localfile.LocalFileInfo.IsDir() {
			directoryNames = append(directoryNames, localfile.RemotePath)
			directoryMappingMap[localfile.RemotePath] = localfile
		}
	}

	// Now sort the directories by name, which ensures that the parent of each
	// directory is available if we need to create its children.
	sort.Strings(directoryNames)

	nUploadErrors := int32(0)

	if len(directoryNames) > 0 {
		// Actually create/update the directories.
		dirProgressBar := pb.New(len(directoryNames))
		dirProgressBar.ShowBar = true
		dirProgressBar.Output = os.Stderr
		dirProgressBar.Prefix("Directories: ")
		dirProgressBar.Start()

		// And finally sync the directories, which serves to create any missing ones.
		for _, dirName := range directoryNames {
			file := directoryMappingMap[dirName]
			err = syncFileUp(file, encrypt, existingFiles, dirProgressBar)
			if err != nil {
				nUploadErrors++
				printErrorAndExit(fmt.Errorf("%s: %v", file.LocalPath, err))
			}
			updateActiveMemory()
		}
		dirProgressBar.Finish()
	}

	fileProgressBar := pb.New64(nBytesToUpload).SetUnits(pb.U_BYTES)
	fileProgressBar.ShowBar = true
	fileProgressBar.Output = os.Stderr
	fileProgressBar.Prefix("Files: ")
	fileProgressBar.Start()

	// Sort the files by size, small to large.
	sort.Sort(localToRemoteBySize(fileMappings))

	// The two indices uploadFrontIndex and uploadBackIndex point to the
	// range of elements in the fileMappings array that haven't yet been
	// uploaded.
	uploadFrontIndex := 0
	uploadBackIndex := len(fileMappings) - 1

	// First, upload any large files that will use the resumable upload
	// protocol using a single thread; more threads here doesn't generally
	// help improve bandwidth utilizaiton and seems to make rate limit
	// errors from the Drive API more frequent...
	for ; uploadBackIndex >= 0; uploadBackIndex-- {
		if fileMappings[uploadBackIndex].LocalFileInfo.Size() < resumableUploadMinSize {
			break
		}

		fm := fileMappings[uploadBackIndex]
		if fm.LocalFileInfo.IsDir() {
			continue
		}

		if err := syncFileUp(fm, encrypt, existingFiles, fileProgressBar); err != nil {
			atomic.AddInt32(&nUploadErrors, 1)
			fmt.Fprintf(os.Stderr, "\nskicka: %s: %v\n", fm.LocalPath, err)
		}
		updateActiveMemory()
	}

	// Smaller files will be handled with multiple threads going at once;
	// doing so improves bandwidth utilization since round-trips to the
	// Drive APIs take a while.  (However, we don't want too have too many
	// workers; this would both lead to lots of 403 rate limit errors...)
	nWorkers := 4

	// Upload worker threads send a value over this channel when
	// they're done; the code that launches them waits for all of them
	// to do so before returning.
	doneChan := make(chan int)

	// Now that multiple threads are running, we need a mutex to protect
	// access to uploadFrontIndex and uploadBackIndex.
	var uploadIndexMutex sync.Mutex

	// All but one of the upload threads will grab files to upload starting
	// from the begining of the fileMappings array, thus doing the smallest
	// files first; one thread starts from the back of the array, doing the
	// largest files first.  In this way, the large files help saturate the
	// available upload bandwidth and hide the fixed overhead of creating
	// the smaller files.
	uploadWorker := func(startFromFront bool) {
		for {
			uploadIndexMutex.Lock()
			if uploadFrontIndex > uploadBackIndex {
				// All files have been uploaded.
				debug.Printf("All files uploaded [%d,%d]; exiting",
					uploadFrontIndex, uploadBackIndex)
				uploadIndexMutex.Unlock()
				doneChan <- 1
				break
			}

			// Get the index into fileMappings for the next file this
			// worker should upload.
			var index int
			if startFromFront {
				index = uploadFrontIndex
				uploadFrontIndex++
			} else {
				index = uploadBackIndex
				uploadBackIndex--
			}
			uploadIndexMutex.Unlock()

			fm := fileMappings[index]
			if fm.LocalFileInfo.IsDir() {
				continue
			}

			err = syncFileUp(fm, encrypt, existingFiles, fileProgressBar)
			if err != nil {
				atomic.AddInt32(&nUploadErrors, 1)
				fmt.Fprintf(os.Stderr, "\nskicka: %s: %v\n", fm.LocalPath, err)
			}
			updateActiveMemory()
		}
	}

	// Launch the workers.
	for i := 0; i < nWorkers; i++ {
		// All workers except the first one start from the front of
		// the array.
		go uploadWorker(i != 0)
	}

	// Wait for all of the workers to finish.
	for i := 0; i < nWorkers; i++ {
		<-doneChan
	}
	fileProgressBar.Finish()

	if nUploadErrors > 0 {
		fmt.Fprintf(os.Stderr, "skicka: %d files not uploaded due to errors. "+
			"This is likely a transient failure; try uploading again", nUploadErrors)
	}
	return int(nUploadErrors)
}

func filterFilesToUpload(fileMappings []localToRemoteFileMapping,
	files gdrive.Files, encrypt, trustTimes bool) ([]localToRemoteFileMapping, error) {
	// files to be uploaded are kept in this slice
	var toUpload []localToRemoteFileMapping

	for _, file := range fileMappings {
		driveFile, err := files.GetOne(file.RemotePath)
		if err == gdrive.ErrNotExist {
			toUpload = append(toUpload, file)
		} else if err == gdrive.ErrMultipleFiles {
			fmt.Fprintf(os.Stderr, "skicka: %s: multiple files/folders with this name exist "+
				"in Google Drive. Skipping all files in this hierarchy.\n",
				file.RemotePath)
		} else {
			// The file already exists on Drive; just make sure it has all
			// of the properties that we expect.
			if err := createMissingProperties(driveFile, file.LocalFileInfo.Mode(),
				encrypt); err != nil {
				return nil, err
			}

			// Go ahead and update the file's permissions if they've changed
			if err := updatePermissions(driveFile, file.LocalFileInfo.Mode()); err != nil {
				return nil, err
			}

			if file.LocalFileInfo.IsDir() {
				// If it's a directory, once it's created and the permissions and times
				// are updated (if needed), we're all done.
				t, err := gdrive.GetModificationTime(driveFile)
				if err != nil {
					return nil, err
				}
				if !t.Equal(file.LocalFileInfo.ModTime()) {
					if err := gd.UpdateModificationTime(driveFile,
						file.LocalFileInfo.ModTime()); err != nil {
						return nil, err
					}
				}
				continue
			}

			// Compare the things we can do quickly (sizes, times).
			sizeMatches, timeMatches, err := fileMetadataMatches(file.LocalFileInfo,
				encrypt, driveFile)

			if err != nil {
				return nil, err
			}

			if sizeMatches == false {
				debug.Printf("size mismatch; adding file %s to upload list",
					file.LocalPath)
				toUpload = append(toUpload, file)
				continue
			} else if timeMatches == true && trustTimes {
				debug.Printf("size and time match; skipping upload of %s",
					file.LocalPath)
				continue
			}

			// The file sizes match and either the modification times
			// differ or they're the same but we don't trust them.
			// Therefore, we'll compare MD5 checksums of file contents.
			var iv []byte
			if encrypt {
				iv, err = getInitializationVector(driveFile)
				if err != nil {
					return nil, fmt.Errorf("unable to get IV: %v", err)
				}
			}

			// Check if the saved MD5 on Drive is the same when it's recomputed locally
			md5contents, err := localFileMD5Contents(file.LocalPath, encrypt, iv)
			if err != nil {
				return nil, err
			}

			contentsMatch := md5contents == driveFile.Md5Checksum
			if contentsMatch == false {
				toUpload = append(toUpload, file)
			} else {
				if timeMatches == false {
					// The timestamp of the local file is different, but the contents
					// are unchanged versus what's on Drive, so just update the
					// modified time on Drive so that we don't keep checking this
					// file.
					debug.Printf("contents match, timestamps do not")
					if err := gd.UpdateModificationTime(driveFile,
						file.LocalFileInfo.ModTime()); err != nil {
						return nil, err
					}
				} else {
					// We're running with -ignore-times, the modification times
					// matched, but the file contents were different. This is both
					// surprising and disturbing; it specifically suggests that
					// either the file contents were modified without the file's
					// modification time being updated, or that there was file
					// corruption of some sort. We'll be conservative and not clobber
					// the Drive file in case it was the latter.
					return nil, fmt.Errorf("has different contents versus Google " +
						"Drive, but doesn't have a newer timestamp. **Not updating" +
						"the file on Drive**. Run 'touch' to update the file" +
						"modification time and re-run skicka if you do want to" +
						"update the file.")
				}
			}
		}
	}

	return toUpload, nil
}

func shouldSkipUpload(path string, info os.FileInfo) bool {
	// Check to see if the filename matches one of the regular expressions
	// of files to ignore.
	for _, re := range config.Upload.Ignored_Regexp {
		match, err := regexp.MatchString(re, path)
		if match == true {
			fmt.Fprintf(os.Stderr, "skicka: ignoring file %s, which "+
				"matches regexp \"%s\".\n", path, re)
			return true
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s: %s", path, err)
			return true
		}
	}

	if (info.Mode() & os.ModeSymlink) != 0 {
		fmt.Fprintf(os.Stderr, "skicka: ignoring symlink \"%s\".\n", path)
		return true
	}

	return false
}

func compileUploadFileTree(localPath, drivePath string,
	encrypt bool) ([]localToRemoteFileMapping, error) {
	// Walk the local directory hierarchy starting at 'localPath' and build
	// an array of files that may need to be synchronized.
	var fileMappings []localToRemoteFileMapping

	// If we're just uploading a single file, some of the details are
	// different...
	if stat, err := os.Stat(localPath); err == nil && stat.IsDir() == false {
		if !shouldSkipUpload(localPath, stat) {
			driveFile, err := gd.GetFile(drivePath)
			if err == nil && gdrive.IsFolder(driveFile) {
				drivePath = filepath.Join(drivePath, filepath.Base(localPath))
			}
			fileMappings = append(fileMappings,
				localToRemoteFileMapping{localPath, drivePath, stat})
			return fileMappings, nil
		}
	}

	walkFuncCallback := func(path string, info os.FileInfo, patherr error) error {
		path = filepath.Clean(path)
		if patherr != nil {
			debug.Printf("%s: %v", path, patherr)
			return nil
		}

		if shouldSkipUpload(path, info) {
			return nil
		}

		// Get the file's path relative to the base directory we're
		// uploading from.
		relPath, err := filepath.Rel(localPath, path)
		if err != nil {
			return err
		}
		drivePath := filepath.Clean(drivePath + "/" + relPath)
		if info.IsDir() == false && encrypt == true {
			drivePath += encryptionSuffix
		}
		fileMappings = append(fileMappings, localToRemoteFileMapping{path, drivePath, info})
		return nil
	}

	err := filepath.Walk(localPath, walkFuncCallback)
	return fileMappings, err
}

// If we didn't shut down cleanly before, there may be files that
// don't have the various properties we expect. Check for that now
// and patch things up as needed.
func createMissingProperties(f *drive.File, mode os.FileMode, encrypt bool) error {
	if !gdrive.IsFolder(f) {
		if encrypt {
			if _, err := gdrive.GetProperty(f, "IV"); err != nil {
				// Compute a unique IV for the file.
				iv := getRandomBytes(aes.BlockSize)
				ivhex := hex.EncodeToString(iv)

				debug.Printf("Creating IV property for file %s, "+
					"which doesn't have one.", f.Title)
				err := gd.AddProperty("IV", ivhex, f)
				if err != nil {
					return err
				}
			}
		}
	}
	if _, err := gdrive.GetProperty(f, "Permissions"); err != nil {
		debug.Printf("Creating Permissions property for file %s, "+
			"which doesn't have one.", f.Title)
		err := gd.AddProperty("Permissions", fmt.Sprintf("%#o", mode&os.ModePerm), f)
		if err != nil {
			return err
		}
	}
	return nil
}

// Create a new *drive.File with the given name inside the folder represented
// by parentFolder.
func createDriveFile(filename string, mode os.FileMode, modTime time.Time, encrypt bool,
	parentFolder *drive.File) (*drive.File, error) {
	var proplist []*drive.Property
	if encrypt {
		// Compute a unique IV for the file.
		iv := getRandomBytes(aes.BlockSize)
		ivhex := hex.EncodeToString(iv)
		proplist = append(proplist, &drive.Property{Key: "IV", Value: ivhex})
	}
	proplist = append(proplist, &drive.Property{Key: "Permissions",
		Value: fmt.Sprintf("%#o", mode&os.ModePerm)})

	return gd.InsertNewFile(filename, parentFolder, modTime, proplist)
}

// Create a *drive.File for the folder with the given title and parent folder.
func createDriveFolder(title string, mode os.FileMode, modTime time.Time,
	parentFolder *drive.File) (*drive.File, error) {
	var proplist []*drive.Property
	proplist = append(proplist, &drive.Property{Key: "Permissions",
		Value: fmt.Sprintf("%#o", mode&os.ModePerm)})

	return gd.InsertNewFolder(title, parentFolder, modTime, proplist)
}

func updatePermissions(driveFile *drive.File, mode os.FileMode) error {
	bits := mode & os.ModePerm
	bitsString := fmt.Sprintf("%#o", bits)
	return gd.UpdateProperty(driveFile, "Permissions", bitsString)
}
