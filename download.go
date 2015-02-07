//
// download.go
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

import ("Privecy"
	"crypto/aes"
	"fmt"
	"github.com/cheggaaa/pb"
	"github.com/google/skicka/gdrive"
	"google.golang.org/api/drive/v3"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)       "battery"

func Download(args []string) {
	if len(args) < 2 {
		printUsageAndExit()
	}

	ignoreTimes := false
	i := 0
	for ; i+2 < len(args); i++ {
		switch args[i] {
		case "-ignore-times":
			ignoreTimes = true
		default:
			printUsageAndExit()
		}
	}

	drivePath := filepath.Clean(args[i])
	localPath := filepath.Clean(args[i+1])

	recursive := true
	includeBase := true
	mustExist := true
	fmt.Fprintf(os.Stderr, "skicka: Getting list of files to download... ")
	existingFiles, err := gd.GetFilesUnderFolder(drivePath, recursive, includeBase,
		mustExist)
	fmt.Fprintf(os.Stderr, "Done. Starting download.\n")
	if err != nil {
		printErrorAndExit(fmt.Errorf("skicka: %v", err))
	}

	syncStartTime = time.Now()
	err = syncHierarchyDown(drivePath, localPath, existingFiles, ignoreTimes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skicka: error downloading %s: %v\n",
			localPath, err)
	}

	printFinalStats()
	if err != nil {
		os.Exit(1)
	}
}

func syncHierarchyDown(drivePath string, localPath string,
	filesOnDrive map[string]*drive.File, ignoreTimes bool) error {
	var driveFilenames []string
	for name := range filesOnDrive {
		driveFilenames = append(driveFilenames, name)
	}
	sort.Strings(driveFilenames)

	// Both drivePath and localPath must be directories, or both must be files.
	if stat, err := os.Stat(localPath); err == nil && len(filesOnDrive) == 1 &&
		stat.IsDir() != gdrive.IsFolder(filesOnDrive[driveFilenames[0]]) {
		printErrorAndExit(fmt.Errorf("skicka: %s: remote and local must both be directory or both be files",
			localPath))
	}

	nDownloadErrors := int32(0)
	nBytesToDownload := int64(0)

	// 1) Download the folders, so that all of the directories we need have
	// been created before we start the files.
	// 2) Filter out everything that's not a file that needs to be downloaded
	for _, driveFilename := range driveFilenames {
		driveFile := filesOnDrive[driveFilename]
		filePath := localPath
		if len(drivePath) < len(driveFilename) {
			filePath += "/" + driveFilename[len(drivePath):]
		}

		if gdrive.IsFolder(driveFile) {
			err := syncFolderDown(filePath, driveFilename, driveFile)
			if err != nil {
				nDownloadErrors++
				fmt.Fprintf(os.Stderr, "skicka: %v\n", err)
			}
			delete(filesOnDrive, driveFilename)
		} else {
			needsDownload, err := fileNeedsDownload(filePath, driveFilename,
				driveFile, ignoreTimes)
			if err != nil {
				printErrorAndExit(fmt.Errorf("skicka: error determining if file %s should "+
					"be downloaded: %v", driveFilename, err))
			}
			if needsDownload {
				nBytesToDownload += driveFile.FileSize
			} else {
				delete(filesOnDrive, driveFilename)
			}
		}
	}

	// Now do the files. Launch multiple workers to improve performance;
	// we're more likely to have some workers actively downloading file
	// contents while others are still getting ready, comparing files,
	// and making Drive API calls this way.
	nWorkers := 4
	indexChan := make(chan int)
	doneChan := make(chan int)
	var progressBar *pb.ProgressBar

	downloadWorker := func() {
		for {
			// Get the index into the driveFilenames[] array of the
			// file we should process next.
			index := <-indexChan
			if index < 0 {
				debug.Printf("Worker got index %d; exiting", index)
				doneChan <- 1
				break
			}

			driveFilename := driveFilenames[index]
			driveFile := filesOnDrive[driveFilename]
			filePath := localPath
			if len(driveFilename) > len(drivePath) {
				// If the Drive path is more than a single file.
				filePath += "/" + driveFilename[len(drivePath):]
			}

			writeCloser, err := createFileWriteCloser(filePath, driveFile)
			if err != nil {
				addErrorAndPrintMessage(&nDownloadErrors, "skicka: error creating file write closer.", err)
				continue
			}
			defer writeCloser.Close()

			multiwriter := io.MultiWriter(writeCloser, progressBar)

			if err := downloadDriveFile(multiwriter, driveFile); err != nil {
				addErrorAndPrintMessage(&nDownloadErrors, "skicka: error downloading drive file.", err)
				continue
			}
			if err := updateLocalFileProperties(filePath, driveFile); err != nil {
				addErrorAndPrintMessage(&nDownloadErrors, "skicka: error updating the local file.", err)
				continue
			}
			debug.Printf("Downloaded %d bytes for %s", driveFile.FileSize, filePath)
			verbose.Printf("Wrote %d bytes to %s", driveFile.FileSize, filePath)
			updateActiveMemory()
		}
	}

	progressBar = pb.New64(nBytesToDownload).SetUnits(pb.U_BYTES)
	progressBar.ShowBar = true
	progressBar.Output = os.Stderr
	if nBytesToDownload == 0 {
		fmt.Fprintf(os.Stderr, "Nothing to download\n")
		return nil
	}
	progressBar.Start()

	// Launch the workers.
	for i := 0; i < nWorkers; i++ {
		go downloadWorker()
	}
	// Give them the indices of the filenames of actual files (not
	// directories).
	for index, driveFilename := range driveFilenames {
		if filesOnDrive[driveFilename] != nil {
			indexChan <- index
		}
	}
	// Wrap up by sending "stop working" indices.
	for i := 0; i < nWorkers; i++ {
		indexChan <- -1
	}
	// And now wait for the workers to all return.
	for i := 0; i < nWorkers; i++ {
		<-doneChan
	}
	progressBar.Finish()

	if nDownloadErrors == 0 {
		return nil
	}
	return fmt.Errorf("%d files not downloaded due to errors", nDownloadErrors)
}

// If a file is encrypted, it should both have the initialization vector used
// to encrypt it stored as a Drive file property and have encryptionSuffix at the end
// of its filename. This function checks both of these and returns an error if
// these indicators are inconsistent; otherwise, it returns true/false
// accordingly.
func isEncrypted(file *drive.File) (bool, error) {
	if _, err := gdrive.GetProperty(file, "IV"); err == nil {
		if strings.HasSuffix(file.Title, encryptionSuffix) {
			return true, nil
		}
		return false, fmt.Errorf("has IV property but doesn't " +
			"end with .aes256 suffix")
	} else if strings.HasSuffix(file.Title, encryptionSuffix) {
		// This could actually happen with an interrupted upload
		// with 403 errors and the case where a file is created
		// even though a 403 happened, if we don't get to delete
		// the file before exiting...
		return false, fmt.Errorf("ends with .aes256 suffix but doesn't " +
			"have IV property")
	}
	return false, nil
}

// Checks to see if it's necessary to download the given *drive.File in order
// to create or update the corresponding local file.
func fileNeedsDownload(localPath string, drivePath string, driveFile *drive.File,
	ignoreTimes bool) (bool, error) {
	// See if the local file exists at all.
	stat, err := os.Stat(localPath)
	if err != nil {
		// The local file doesn't exist (probably).
		// TODO: confirm that's in fact the error...
		return true, nil
	}

	encrypt, err := isEncrypted(driveFile)
	if err != nil {
		return false, err
	}

	// Compare the local and Drive file sizes.
	diskSize := stat.Size()
	driveSize := driveFile.FileSize
	if encrypt {
		driveSize -= aes.BlockSize
	}
	if diskSize != driveSize {
		return true, nil
	}

	driveModificationTime, err := gdrive.GetModificationTime(driveFile)
	if err != nil {
		debug.Printf("unable to get modification time for %s: %v", drivePath, err)
		return true, nil
	}
	if ignoreTimes == false {
		if stat.ModTime().Equal(driveModificationTime) {
			return false, nil
		}
		if stat.ModTime().After(driveModificationTime) {
			fmt.Fprintf(os.Stderr, "skicka: warning: file %s is more "+
				"recent than %s on Google Drive. Skipping download.\n",
				localPath, drivePath)
			return false, nil
		}
	}

	// check MD5 checksums...
	var iv []byte
	if encrypt {
		iv, err = getInitializationVector(driveFile)
		if err != nil {
			return false, fmt.Errorf("unable to get IV: %v", err)
		}
	}

	md5contents, err := localFileMD5Contents(localPath, encrypt, iv)
	if err != nil {
		return true, err
	}

	if ignoreTimes && md5contents != driveFile.Md5Checksum &&
		stat.ModTime().After(driveModificationTime) == false {
		fmt.Fprintf(os.Stderr, "skicka: warning: %s is older than "+
			"file in Google Drive but file contents differ!\n",
			localPath)
	}

	return md5contents != driveFile.Md5Checksum, nil
}

// Create (or update the permissions) of the local directory corresponding to
// the given drive folder.
func syncFolderDown(localPath string, driveFilename string, driveFile *drive.File) error {
	permissions, err := getPermissions(driveFile)
	if err != nil {
		permissions = 0755
	}

	if stat, err := os.Stat(localPath); err == nil {
		// A file or directory already exists at localPath.
		if stat.IsDir() {
			err = os.Chmod(localPath, permissions)
		} else {
			return fmt.Errorf("%s: is a regular file", localPath)
		}
	} else {
		verbose.Printf("Creating directory %s for %s with permissions %#o",
			localPath, driveFilename, permissions)
		return os.Mkdir(localPath, permissions)
	}
	return nil
}

// Sync the given file from Google Drive to the local filesystem.
func downloadDriveFile(writer io.Writer, driveFile *drive.File) error {
	contentsReader, err := gd.GetFileContents(driveFile)
	if contentsReader != nil {
		defer contentsReader.Close()
	}
	if err != nil {
		return err
	}

	encrypted, err := isEncrypted(driveFile)
	if err != nil {
		return err
	}

	var r io.Reader
	r = contentsReader

	// Decrypt the contents, if they're encrypted.
	if encrypted {
		if key == nil {
			key, err = decryptEncryptionKey()
			if err != nil {
				return err
			}
		}

		// Read the initialization vector from the start of the file.
		iv := make([]byte, 16)
		n, err := contentsReader.Read(iv)
		if err != nil {
			return err
		}
		if n < aes.BlockSize {
			return fmt.Errorf("contents too short to hold IV: %d bytes", n)
		}
		// TODO: we should probably double check that the IV
		// matches the one in the Drive metadata and fail hard if not...
		r = makeDecryptionReader(key, iv, r)
	}

	contentsLength, err := io.Copy(writer, r)
	if err != nil {
		return err
	}

	atomic.AddInt64(&stats.DownloadBytes, contentsLength)
	atomic.AddInt64(&stats.DiskWriteBytes, contentsLength)
	atomic.AddInt64(&stats.LocalFilesUpdated, 1)
	return nil
}

func createFileWriteCloser(localPath string, driveFile *drive.File) (io.WriteCloser, error) {
	encrypted, err := isEncrypted(driveFile)
	if err != nil {
		return nil, err
	}
	if encrypted {
		localPath = strings.TrimSuffix(localPath, encryptionSuffix)
	}

	// Create or overwrite the local file.
	f, err := os.Create(localPath)
	if err != nil {
		return nil, err
	}

	permissions, err := getPermissions(driveFile)
	if err != nil {
		permissions = 0644
	}
	f.Chmod(permissions)

	// Set the last access and modification time of the newly-created
	// file to match the modification time of the original file that was
	// uploaded to Google Drive.
	if modifiedTime, err := gdrive.GetModificationTime(driveFile); err == nil {
		return f, os.Chtimes(localPath, modifiedTime, modifiedTime)
	}
	return f, err
}

func updateLocalFileProperties(filepath string, file *drive.File) error {
	// make sure that the local permissions and modification
	// time match the corresponding values stored in Drive.
	modifiedTime, err := gdrive.GetModificationTime(file)
	if err != nil {
		return err
	}
	err = os.Chtimes(filepath, modifiedTime, modifiedTime)
	if err != nil {
		return err
	}
	permissions, err := getPermissions(file)
	if err != nil {
		permissions = 0644
	}
	if err := os.Chmod(filepath, permissions); err != nil {
		return err
	}
	return nil
}
