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
	"bytes"
	"crypto/aes"
	"crypto/md5"
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

// fileCloser is kind of a hack: it implements the io.ReadCloser
// interface, wherein the Read() calls go to R, and the Close() call
// goes to C.
type fileCloser struct {
	R io.Reader
	C *os.File
}

func (fc *fileCloser) Read(b []byte) (int, error) {
	return fc.R.Read(b)
}

func (fc *fileCloser) Close() error {
	return fc.C.Close()
}

type byteCountingReader struct {
	R         io.Reader
	bytesRead int
}

func (bcr *byteCountingReader) Read(dst []byte) (int, error) {
	read, err := bcr.R.Read(dst)
	bcr.bytesRead += read
	return read, err
}

func uploadUsage() {
	fmt.Printf("Usage: skicka upload [-ignore-times] local_path drive_path\n")
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
	existingFiles, err := gd.GetFilesUnderFolder(drivePath, recursive, includeBase,
		mustExist)
	fmt.Fprintf(os.Stderr, "Done.\n")
	if err != nil {
		printErrorAndExit(err)
	}

	// FIXME: get from sync up...
	errs := 0

	syncStartTime = time.Now()
	err = syncHierarchyUp(localPath, drivePath, existingFiles, encrypt,
		ignoreTimes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skicka: error uploading %s: %v\n",
			localPath, err)
	}

	printFinalStats()
	if err != nil {
		errs++
	}
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
	driveFile *drive.File) (bool, error) {
	localSize := info.Size()
	driveSize := driveFile.FileSize
	if encrypt {
		// We store a copy of the initialization vector at the start of
		// the file stored in Google Drive; account for this when
		// comparing the file sizes.
		driveSize -= aes.BlockSize
	}
	if localSize != driveSize {
		// File sizes mismatch; update needed.
		return false, nil
	}

	driveTime, err := gdrive.GetModificationTime(driveFile)
	if err != nil {
		return true, err
	}

	// Finally, check if the local modification time is different than the
	// modification time of the file the last time it was updated on Drive;
	// if it is, we return false and an upload will be done..
	localTime := info.ModTime()
	debug.Printf("localTime: %v, driveTime: %v", localTime, driveTime)
	return localTime.Equal(driveTime), nil
}

// Return the md5 hash of the file at the given path in the form of a
// string. If encryption is enabled, use the encrypted file contents when
// computing the hash.
func localFileMD5Contents(path string, encrypt bool, iv []byte) (string, error) {
	contentsReader, _, err := getFileContentsReaderForUpload(path, encrypt, iv)
	if contentsReader != nil {
		defer contentsReader.Close()
	}
	if err != nil {
		return "", err
	}

	md5 := md5.New()
	n, err := io.Copy(md5, contentsReader)
	if err != nil {
		return "", err
	}
	atomic.AddInt64(&stats.DiskReadBytes, n)

	return fmt.Sprintf("%x", md5.Sum(nil)), nil
}

// Returns an io.ReadCloser for given file, such that the bytes read are
// ready for upload: specifically, if encryption is enabled, the contents
// are encrypted with the given key and the initialization vector is
// prepended to the returned bytes. Otherwise, the contents of the file are
// returned directly.
func getFileContentsReaderForUpload(path string, encrypt bool,
	iv []byte) (io.ReadCloser, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return f, 0, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	fileSize := stat.Size()

	if encrypt {
		if key == nil {
			key, err = decryptEncryptionKey()
			if err != nil {
				return nil, 0, err
			}
		}

		r := makeEncrypterReader(key, iv, f)

		// Prepend the initialization vector to the returned bytes.
		r = io.MultiReader(bytes.NewReader(iv[:aes.BlockSize]), r)

		return &fileCloser{R: r, C: f}, fileSize + aes.BlockSize, nil
	}
	return f, fileSize, nil
}

// Given a file on the local disk, synchronize it with Google Drive: if the
// corresponding file doesn't exist on Drive, it's created; if it exists
// but has different contents, the contents are updated.  The Unix
// permissions and file modification time on Drive are also updated
// appropriately.
// Besides being sent up to Google Drive, the file is tee'd (via io.Tee)
// into an optional writer variable.  This variable can safely be nil.
func syncFileUp(fileMapping localToRemoteFileMapping, encrypt bool,
	existingDriveFiles map[string]*drive.File, pb *pb.ProgressBar) error {
	debug.Printf("syncFileUp: %#v", fileMapping.LocalFileInfo)

	// We need to create the file or folder on Google Drive.
	var err error

	// Get the *drive.File for the folder to create the new file in.
	// This folder should definitely exist at this point, since we
	// create all folders needed before starting to upload files.
	dirPath := filepath.Dir(fileMapping.RemotePath)
	if dirPath == "." {
		dirPath = "/"
	}
	parentFile, ok := existingDriveFiles[dirPath]
	if !ok {
		parentFile, err = gd.GetFile(dirPath)
		if err != nil {
			// We can't really recover at this point; the
			// parent folder definitely should have been
			// created by now, and we can't proceed without
			// it...
			printErrorAndExit(err)
		}
	}

	baseName := filepath.Base(fileMapping.RemotePath)
	var driveFile *drive.File

	if fileMapping.LocalFileInfo.IsDir() {
		driveFile, err = createDriveFolder(baseName,
			fileMapping.LocalFileInfo.Mode(), fileMapping.LocalFileInfo.ModTime(),
			parentFile)
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
		existingDriveFiles[fileMapping.RemotePath] = driveFile
	} else {
		if driveFile, ok = existingDriveFiles[fileMapping.RemotePath]; !ok {
			driveFile, err = createDriveFile(baseName,
				fileMapping.LocalFileInfo.Mode(),
				fileMapping.LocalFileInfo.ModTime(), encrypt, parentFile)
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

		for ntries := 0; ntries < 5; ntries++ {
			var reader io.Reader
			var countingReader *byteCountingReader

			contentsReader, length, err :=
				getFileContentsReaderForUpload(fileMapping.LocalPath, encrypt, iv)
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
				break
			}

			if re, ok := err.(gdrive.RetryHTTPTransmitError); ok {
				debug.Printf("%s: got retry http error--retrying: %s",
					fileMapping.LocalPath, re.Error())
				if pb != nil {
					// The "progress" made so far on
					// this file should be rolled back
					pb.Add64(int64(0 - countingReader.bytesRead))
				}
			} else {
				debug.Printf("%s: giving up due to error: %v",
					fileMapping.LocalPath, err)
				// This file won't be uploaded, so subtract
				// the expected progress from the total
				// expected bytes
				if pb != nil {
					pb.Add64(int64(0 - countingReader.bytesRead))
					pb.Total -= length
				}
				return err
			}
		}
	}

	verbose.Printf("Updated local %s -> Google Drive %s", fileMapping.LocalPath,
		fileMapping.RemotePath)
	return gd.UpdateModificationTime(driveFile, fileMapping.LocalFileInfo.ModTime())
}

// Synchronize a local directory hierarchy with Google Drive.
// localPath is the file or directory to start with, driveRoot is
// the directory into which the file/directory will be sent
func syncHierarchyUp(localPath string, driveRoot string,
	existingFiles map[string]*drive.File, encrypt bool, ignoreTimes bool) error {
	if encrypt {
		var err error
		key, err = decryptEncryptionKey()
		if err != nil {
			return err
		}
	}

	fileMappings, err := compileUploadFileTree(localPath, driveRoot, encrypt)
	checkFatalError(err, "error getting local filetree")
	fileMappings, err = filterFilesToUpload(fileMappings, existingFiles, encrypt,
		ignoreTimes)
	checkFatalError(err, "error determining files to sync")

	if len(fileMappings) == 0 {
		fmt.Fprintln(os.Stderr,
			"skicka: there are no new files that need to be uploaded.")
		return nil
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
	// workers; this would both lead to lots of 403 rate limit errors as
	// well as possibly increase memory use too much if we're uploading
	// lots of large files...)
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

	if nUploadErrors == 0 {
		return nil
	}
	return fmt.Errorf("%d files not uploaded due to errors. "+
		"This is likely a transient failure; try uploading again", nUploadErrors)
}

func filterFilesToUpload(fileMappings []localToRemoteFileMapping,
	existingDriveFiles map[string]*drive.File,
	encrypt, ignoreTimes bool) ([]localToRemoteFileMapping, error) {

	// files to be uploaded are kept in this slice
	var toUpload []localToRemoteFileMapping

	for _, file := range fileMappings {
		driveFile, exists := existingDriveFiles[file.RemotePath]
		if !exists {
			toUpload = append(toUpload, file)
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
					if err := gd.UpdateModificationTime(driveFile, file.LocalFileInfo.ModTime()); err != nil {
						return nil, err
					}
				}
				continue
			}

			// Do superficial checking on the files
			metadataMatches, err := fileMetadataMatches(file.LocalFileInfo, encrypt, driveFile)

			if err != nil {
				return nil, err
			} else if metadataMatches && !ignoreTimes {
				continue
			}

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
			if contentsMatch {
				// The timestamp of the local file is different, but the contents
				// are unchanged versus what's on Drive, so just update the
				// modified time on Drive so that we don't keep checking this
				// file.
				debug.Printf("contents match, timestamps do not")
				if err := gd.UpdateModificationTime(driveFile, file.LocalFileInfo.ModTime()); err != nil {
					return nil, err
				}
			} else if metadataMatches == true {
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
			} else {
				toUpload = append(toUpload, file)
			}
		}
	}

	return toUpload, nil
}

func compileUploadFileTree(localPath, driveRoot string, encrypt bool) ([]localToRemoteFileMapping, error) {
	// Walk the local directory hierarchy starting at 'localPath' and build
	// an array of files that may need to be synchronized.
	var fileMappings []localToRemoteFileMapping

	walkFuncCallback := func(path string, info os.FileInfo, patherr error) error {
		path = filepath.Clean(path)
		if patherr != nil {
			debug.Printf("%s: %v", path, patherr)
			return nil
		}

		// Check to see if the filename matches one of the regular
		// expressions of files to ignore.
		for _, re := range config.Upload.Ignored_Regexp {
			match, err := regexp.MatchString(re, path)
			if match == true {
				fmt.Printf("skicka: ignoring file %s, which "+
					"matches regexp \"%s\".\n", path, re)
				return nil
			}
			if err != nil {
				return err
			}
		}

		if (info.Mode() & os.ModeSymlink) != 0 {
			fmt.Printf("skicka: ignoring symlink \"%s\".\n", path)
			return nil
		}

		// Get the file's path relative to the base directory we're
		// uploading from.
		relPath, err := filepath.Rel(localPath, path)
		if err != nil {
			return err
		}
		drivePath := filepath.Clean(driveRoot + "/" + relPath)
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

		ivprop := new(drive.Property)
		ivprop.Key = "IV"
		ivprop.Value = ivhex
		proplist = append(proplist, ivprop)
	}
	permprop := new(drive.Property)
	permprop.Key = "Permissions"
	permprop.Value = fmt.Sprintf("%#o", mode&os.ModePerm)
	proplist = append(proplist, permprop)

	return gd.InsertNewFile(filename, parentFolder, modTime, proplist)
}

// Create a *drive.File for the folder with the given title and parent folder.
func createDriveFolder(title string, mode os.FileMode, modTime time.Time,
	parentFolder *drive.File) (*drive.File, error) {
	var proplist []*drive.Property
	permprop := new(drive.Property)
	permprop.Key = "Permissions"
	permprop.Value = fmt.Sprintf("%#o", mode&os.ModePerm)
	proplist = append(proplist, permprop)

	return gd.InsertNewFolder(title, parentFolder, modTime, proplist)
}

func updatePermissions(driveFile *drive.File, mode os.FileMode) error {
	bits := mode & os.ModePerm
	bitsString := fmt.Sprintf("%#o", bits)
	return gd.UpdateProperty(driveFile, "Permissions", bitsString)
}
