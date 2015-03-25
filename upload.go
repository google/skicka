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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

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

	includeBase := true
	driveFiles, err := gd.GetFilesUnderFolder(drivePath, includeBase)
	if err != nil && err != gdrive.ErrNotExist {
		printErrorAndExit(err)
	}

	syncStartTime = time.Now()
	errs := syncHierarchyUp(localPath, drivePath, driveFiles, encrypt, trustTimes)
	printFinalStats()

	return errs
}

// Representation of a local file that needs to be synced up to Drive.
type localToRemoteFileMapping struct {
	LocalPath     string
	DrivePath     string
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

// Given a file on the local disk, synchronize it with Google Drive: if the
// corresponding file doesn't exist on Drive, it's created; if it exists
// but has different contents, the contents are updated.  The Unix
// permissions and file modification time on Drive are also updated
// appropriately.
func syncFileUp(localPath string, stat os.FileInfo, drivePath string, encrypt bool,
	pb *pb.ProgressBar) error {
	debug.Printf("syncFileUp: %s -> %s", localPath, drivePath)

	// Get the *drive.File for the folder to create the new file in.
	// This folder should definitely exist at this point, since we
	// create all folders needed before starting to upload files.
	parentFolder, err := gd.GetFile(filepath.Dir(drivePath))
	if err == gdrive.ErrNotExist {
		checkFatalError(err, fmt.Sprintf("%s: get parent directory",
			filepath.Dir(drivePath)))
	} else if err != nil {
		return err
	}

	baseName := filepath.Base(drivePath)
	var driveFile *gdrive.File

	if stat.IsDir() {
		// We only get here if the folder doesn't exist at all on Drive; if
		// it already exists, we update the metadata earlier and don't go
		// through this path.
		var proplist []gdrive.Property
		proplist = append(proplist, gdrive.Property{Key: "Permissions",
			Value: fmt.Sprintf("%#o", stat.Mode()&os.ModePerm)})
		driveFile, err = gd.CreateFolder(baseName, parentFolder, stat.ModTime(),
			proplist)

		checkFatalError(err, fmt.Sprintf("%s: create folder", drivePath))

		pb.Increment()
		atomic.AddInt64(&stats.UploadBytes, stat.Size())
		verbose.Printf("Created Google Drive folder %s", drivePath)
	} else {
		// We're uploading a file.  Create an empty file on Google Drive if
		// it doesn't already exist. We explicitly set the modification
		// time of the file to the start of the Unix epoch, so that if the
		// download fails partway through, then we won't later be confused
		// about which file is the correct one from having local and Drive
		// copies with the same time but different contents.
		if driveFile, err = gd.GetFile(drivePath); err == gdrive.ErrNotExist {
			debug.Printf("%s doesn't exist on Drive. Creating", drivePath)
			var proplist []gdrive.Property
			if encrypt {
				// Compute a unique IV for the file.
				iv := getRandomBytes(aes.BlockSize)
				ivhex := hex.EncodeToString(iv)
				proplist = append(proplist, gdrive.Property{Key: "IV", Value: ivhex})
			}
			proplist = append(proplist, gdrive.Property{Key: "Permissions",
				Value: fmt.Sprintf("%#o", stat.Mode()&os.ModePerm)})
			driveFile, err = gd.CreateFile(baseName, parentFolder, time.Unix(0, 0),
				proplist)

			if err != nil {
				return err
			}
		}

		// And now upload the contents of the file, either overwriting the
		// contents of the existing file, or adding contents to the
		// just-created file.
		err = uploadFileContents(localPath, driveFile, encrypt, pb)
		if err != nil {
			return err
		}
	}

	verbose.Printf("Updated local %s -> Google Drive %s", localPath, drivePath)

	// Only update the modification time on Google Drive to match the local
	// modification time after the upload has finished successfully.
	return gd.UpdateModificationTime(driveFile, stat.ModTime())
}

// uploadFileContents does its best to upload the local file stored at
// localPath to the given *drive.File on Google Drive.  (It assumes that
// the *drive.File has already been created.)
func uploadFileContents(localPath string, driveFile *gdrive.File, encrypt bool,
	pb *pb.ProgressBar) error {
	var iv []byte
	var err error
	if encrypt {
		iv, err = getInitializationVector(driveFile)
		if err != nil {
			return fmt.Errorf("unable to get IV: %v", err)
		}
	}

	for ntries := 0; ntries < 5; ntries++ {
		contentsReader, length, err :=
			getFileContentsReaderForUpload(localPath, encrypt, iv)
		if contentsReader != nil {
			defer contentsReader.Close()
		}
		if err != nil {
			return err
		}

		// Keep track of how many bytes are uploaded in case we fail
		// part-way through and need to roll back the progress bar.
		countingReader := &byteCountingReader{R: contentsReader}

		// Also tee reads to the progress bar as they are done so that it
		// stays in sync with how much data has been transmitted.
		uploadReader := io.TeeReader(countingReader, pb)

		if length >= resumableUploadMinSize {
			err = gd.UploadFileContentsResumable(driveFile, uploadReader, length)
		} else {
			err = gd.UploadFileContents(driveFile, uploadReader, length, ntries)
		}
		atomic.AddInt64(&stats.DiskReadBytes, countingReader.bytesRead)

		if err == nil {
			// Success!
			atomic.AddInt64(&stats.DriveFilesUpdated, 1)
			atomic.AddInt64(&stats.UploadBytes, length)
			return nil
		}

		// The "progress" made so far on this file should be rolled back;
		// if we don't do this, when retries happen, we end up going over
		// 100% progress...
		pb.Add64(-countingReader.bytesRead)

		if re, ok := err.(gdrive.RetryHTTPTransmitError); ok {
			debug.Printf("%s: got retry http error--retrying: %s",
				localPath, re.Error())
		} else {
			debug.Printf("%s: giving up due to error: %v", localPath, err)
			// We're giving up on this file, so subtract its length from
			// what the progress bar is expecting.
			pb.Total -= length
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

	fileMappings, nUploadErrors := compileUploadFileTree(localPath, driveRoot,
		existingFiles, encrypt, trustTimes)
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
			directoryNames = append(directoryNames, localfile.DrivePath)
			directoryMappingMap[localfile.DrivePath] = localfile
		}
	}

	// Now sort the directories by name, which ensures that the parent of each
	// directory has already been created if we need to create its children.
	sort.Strings(directoryNames)

	if len(directoryNames) > 0 {
		// Actually create/update the directories.
		dirProgressBar := pb.New(len(directoryNames))
		dirProgressBar.ShowBar = true
		dirProgressBar.Output = os.Stderr
		dirProgressBar.Prefix("Directories: ")
		dirProgressBar.Start()

		// Sync each of the directories, which serves to create any missing ones.
		for _, dirName := range directoryNames {
			file := directoryMappingMap[dirName]
			err := syncFileUp(file.LocalPath, file.LocalFileInfo, file.DrivePath, encrypt,
				dirProgressBar)
			if err != nil {
				// Errors creating directories are basically unrecoverable,
				// as they'll prevent us from later uploading any files in
				// them.
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

		if err := syncFileUp(fm.LocalPath, fm.LocalFileInfo, fm.DrivePath, encrypt,
			fileProgressBar); err != nil {
			nUploadErrors++
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
				// Directories have already been taken care of.
				continue
			}

			err := syncFileUp(fm.LocalPath, fm.LocalFileInfo, fm.DrivePath, encrypt,
				fileProgressBar)
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

// Determine if the local file needs to be uploaded to Google Drive.
// Starts with the efficient checks that may be able to let us quickly
// determine one way or the other.
func fileNeedsUpload(localPath, drivePath string, stat os.FileInfo,
	encrypt, trustTimes bool) (bool, error) {
	// Don't upload if the filename matches one of the regular expressions
	// of files to ignore.
	for _, re := range config.Upload.Ignored_Regexp {
		match, err := regexp.MatchString(re, localPath)
		if match == true {
			fmt.Fprintf(os.Stderr, "skicka: %s: ignoring file, which "+
				"matches regexp \"%s\".\n", localPath, re)
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}

	// Don't try to upload files that are symlinks.
	if (stat.Mode() & os.ModeSymlink) != 0 {
		fmt.Fprintf(os.Stderr, "skicka: %s: ignoring symlink.\n", localPath)
		return false, nil
	}

	// See if the file exists: if not, then we definitely need to do the
	// upload.
	driveFile, err := gd.GetFile(drivePath)
	if err == gdrive.ErrNotExist {
		debug.Printf("drive file %s doesn't exist -> needs upload", drivePath)
		return true, nil
	} else if err == gdrive.ErrMultipleFiles {
		// If there are multiple files with this name on Drive (as is
		// allowed), then we're going to ignore this file, since it's non
		// obvious what the right thing to do it.
		fmt.Fprintf(os.Stderr, "skicka: %s: multiple files/folders with this name exist "+
			"in Google Drive. Skipping all files in this hierarchy.\n",
			drivePath)
		return false, nil
	} else if err != nil {
		// Some other error.
		return false, err
	}

	// At this point, we know that a file with the corresponding pathname
	// exists on Drive.

	// Error out if there's a mismatch on file-ness and folder-ness between
	// local and Drive.
	if stat.IsDir() && !driveFile.IsFolder() {
		return false, fmt.Errorf("%s: is directory, but %s on Drive is a regular file",
			localPath, drivePath)
	}
	if !stat.IsDir() && driveFile.IsFolder() {
		return false, fmt.Errorf("%s: is regular file, but %s on Drive is a folder",
			localPath, drivePath)
	}

	// With that check out of the way, take the opportunity to make sure
	// the file has all of the properties that we expect.
	if err = createMissingProperties(driveFile, stat.Mode(), encrypt); err != nil {
		return false, err
	}

	// Go ahead and update the file's permissions if they've changed.
	bitsString := fmt.Sprintf("%#o", stat.Mode()&os.ModePerm)
	err = gd.UpdateProperty(driveFile, "Permissions", bitsString)
	if err != nil {
		return false, err
	}

	// If it's a directory, once it's created and the permissions and times
	// are updated (if needed), we're all done.
	if stat.IsDir() {
		return false, gd.UpdateModificationTime(driveFile, stat.ModTime())
	}

	// Compare file sizes.
	localSize, driveSize := stat.Size(), driveFile.FileSize
	if encrypt {
		// We store a copy of the initialization vector at the start of
		// the file stored in Google Drive; account for this when
		// comparing the file sizes.
		driveSize -= aes.BlockSize
	}
	sizeMatches := localSize == driveSize
	if sizeMatches == false {
		// File sizes differ: we need to upload the local file.
		debug.Printf("size mismatch; adding file %s to upload list", localPath)
		return true, nil
	}

	// Compare modification times.
	driveTime := driveFile.ModTime
	localTime := stat.ModTime()
	debug.Printf("localTime: %v, driveTime: %v", localTime, driveTime)
	timeMatches := localTime.Equal(driveTime)
	if timeMatches && trustTimes {
		debug.Printf("size and time match; skipping upload of %s", localPath)
		return false, nil
	}

	// Either the modification times differ or they're the same but we
	// don't trust them.  Therefore, we'll now go through the work of
	// computing MD5 checksums of file contents to make a final decision.
	var iv []byte
	if encrypt {
		iv, err = getInitializationVector(driveFile)
		if err != nil {
			return false, fmt.Errorf("unable to get IV: %v", err)
		}
	}

	// Check if the saved MD5 on Drive is the same when it's recomputed locally
	md5contents, err := localFileMD5Contents(localPath, encrypt, iv)
	if err != nil {
		return false, err
	}
	if md5contents != driveFile.Md5 {
		// The contents of the local file and the remote file differ.

		if timeMatches {
			// We're running with -ignore-times, the modification times
			// matched, but the file contents were different. This is both
			// surprising and disturbing; it specifically suggests that
			// either the file contents were modified in one of the two
			// places without the file's modification time being updated,
			// or that there was file corruption of some sort. We'll be
			// conservative and not clobber the Drive file in case it was
			// the latter.
			return true, fmt.Errorf("%s: has different contents versus Google "+
				"Drive file %s, but doesn't have a newer timestamp. **Not updating"+
				"the file on Drive**. Run 'touch' to update the file"+
				"modification time and re-run skicka if you do want to"+
				"update the file.", localPath, drivePath)
		}

		return true, nil
	}

	// The timestamp of the local file is different, but the checksums
	// match, so just update the modified time on Drive.
	return false, gd.UpdateModificationTime(driveFile, stat.ModTime())
}

func compileUploadFileTree(localPath, drivePath string, existingFiles gdrive.Files,
	encrypt bool, trustTimes bool) ([]localToRemoteFileMapping, int32) {
	// Walk the local directory hierarchy starting at 'localPath' and build
	// an array of files that may need to be synchronized.
	var fileMappings []localToRemoteFileMapping

	nUploadErrors := int32(0)

	// If we're just uploading a single file, some of the details are
	// different...
	if stat, err := os.Stat(localPath); err == nil && stat.IsDir() == false {
		driveFile, err := gd.GetFile(drivePath)
		if err == nil && driveFile.IsFolder() {
			// The local path is for a file and the Drive path is for a
			// folder; update the drive path to end with the base of the
			// local filename.
			drivePath = filepath.Join(drivePath, filepath.Base(localPath))
		}
		if encrypt {
			drivePath += encryptionSuffix
		}

		upload, err := fileNeedsUpload(localPath, drivePath, stat,
			encrypt, trustTimes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s", err)
			nUploadErrors++
		} else if upload {
			fileMappings = append(fileMappings,
				localToRemoteFileMapping{localPath, drivePath, stat})
		}
		return fileMappings, nUploadErrors
	}

	fmt.Fprintf(os.Stderr, "skicka: Getting list of local files... ")
	err := filepath.Walk(localPath,
		func(path string, stat os.FileInfo, patherr error) error {
			path = filepath.Clean(path)
			if patherr != nil {
				debug.Printf("%s: %v", path, patherr)
				return nil
			}

			// Get the file's path relative to the base directory we're
			// uploading from.
			relPath, err := filepath.Rel(localPath, path)
			if err != nil {
				return err
			}
			drivePath := filepath.Join(drivePath, relPath)
			if stat.IsDir() == false && encrypt == true {
				drivePath += encryptionSuffix
			}

			upload, err := fileNeedsUpload(path, drivePath, stat,
				encrypt, trustTimes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skicka: %s", err)
				nUploadErrors++
			} else if upload {
				fileMappings = append(fileMappings,
					localToRemoteFileMapping{path, drivePath, stat})
			}

			// Always return nil: we don't want to stop walking the
			// hierarchy just because we hit an error deciding if one file
			// needs to be uploaded.
			return nil
		})
	fmt.Fprintf(os.Stderr, "Done.\n")

	if err != nil {
		fmt.Fprintf(os.Stderr, "skicka: %s", err)
		nUploadErrors++
	}

	return fileMappings, nUploadErrors
}

// If we didn't shut down cleanly before, there may be files that
// don't have the various properties we expect. Check for that now
// and patch things up as needed.
func createMissingProperties(f *gdrive.File, mode os.FileMode, encrypt bool) error {
	if !f.IsFolder() && encrypt {
		if _, err := f.GetProperty("IV"); err != nil {
			if f.FileSize == 0 {
				// Compute a unique IV for the file.
				iv := getRandomBytes(aes.BlockSize)
				ivhex := hex.EncodeToString(iv)

				debug.Printf("Creating IV property for file %s, "+
					"which doesn't have one.", f.Path)
				err := gd.AddProperty("IV", ivhex, f)
				if err != nil {
					return err
				}
			} else {
				// This is state of affairs really shouldn't ever happen, but
				// if somehow it does, it's important that we catch it: the
				// file is missing the IV property, but has some
				// contents. Presumably the IV is at the start of the file
				// contents and we could initialize the property from that
				// here, but any successfully created file should already have
				// the property, so we'll just error out, since it's not clear
				// what's going on here...
				return fmt.Errorf("encrypted file on Drive is missing" +
					"IV property, but has non-zero length. Can't create the IV " +
					"property without examining file contents.")
			}
		}
	}
	if _, err := f.GetProperty("Permissions"); err != nil {
		debug.Printf("Creating Permissions property for file %s, "+
			"which doesn't have one.", f.Path)
		err := gd.AddProperty("Permissions", fmt.Sprintf("%#o", mode&os.ModePerm), f)
		if err != nil {
			return err
		}
	}
	return nil
}
