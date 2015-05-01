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

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"github.com/cheggaaa/pb"
	"github.com/google/skicka/gdrive"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

func downloadUsage() {
	fmt.Printf("Usage: skicka download [-ignore-times] [-download-google-apps-files] drive_path local_path\n")
	fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
}

func download(args []string) int {
	var drivePath, localPath string
	ignoreTimes := false
	downloadGoogleAppsFiles := false
	for i := 0; i < len(args); i++ {
		if args[i] == "-ignore-times" {
			ignoreTimes = true
		} else if args[i] == "-download-google-apps-files" {
			downloadGoogleAppsFiles = true
		} else if drivePath == "" {
			drivePath = filepath.Clean(args[i])
		} else if localPath == "" {
			localPath = filepath.Clean(args[i])
		} else {
			downloadUsage()
			return 1
		}
	}

	if drivePath == "" || localPath == "" {
		downloadUsage()
		return 1
	}
	trustTimes := !ignoreTimes

	// Start out by seeing what we've got at the given path in Drive. If
	// it's not a single file or folder, then error out.
	files := gd.GetFiles(drivePath)
	if len(files) == 0 {
		printErrorAndExit(fmt.Errorf("%s: not found on Drive", drivePath))
	} else if len(files) > 1 {
		printErrorAndExit(fmt.Errorf("%s: %d files found on Drive with this name",
			drivePath, len(files)))
	}

	syncStartTime = time.Now()

	var errs int
	if files[0].IsFolder() {
		// Download a folder from Drive to the local system.
		errs = syncHierarchyDown(drivePath, localPath, trustTimes, downloadGoogleAppsFiles)
	} else {
		// Only download a single file.
		stat, err := os.Stat(localPath)
		if err == nil && stat.IsDir() {
			// drivePath is a single file but localPath is a directory, so
			// append the base name of the drive file to the local path.
			localPath = path.Join(localPath, filepath.Base(drivePath))
		}

		if !downloadGoogleAppsFiles && files[0].IsGoogleAppsFile() {
			message("%s: skipping Google Apps file.", files[0].Path)
		} else {
			err = syncOneFileDown(files[0], localPath, trustTimes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skicka: %s: %s\n", drivePath, err)
				errs++
			}
		}
	}

	printFinalStats()
	return errs
}

// Synchronize a single file from Google Drive to the local file system at
// `localPath`.
func syncOneFileDown(file *gdrive.File, localPath string, trustTimes bool) error {
	needsDownload, err := fileNeedsDownload(localPath, file, trustTimes)
	if err != nil {
		return fmt.Errorf("%s: error determining if file needs "+
			"download: %v\n", file.Path, err)
	}

	if needsDownload {
		pb := getProgressBar(file.FileSize)
		if pb != nil {
			defer pb.Finish()
		}
		return downloadFile(file, localPath, pb)
	}

	// No download needed, but make sure the local permissions
	// match the permissions on Drive.
	mode, err := getPermissions(file)
	if err != nil {
		mode = 0644
	}
	return os.Chmod(localPath, mode)
}

// Synchronize an entire folder hierarchy from Drive to a local directory.
func syncHierarchyDown(driveBasePath string, localBasePath string, trustTimes bool,
	downloadGoogleAppsFiles bool) int {
	// First, make sure the user isn't asking us to download a directory on
	// top of a file.
	if stat, err := os.Stat(localBasePath); err == nil && !stat.IsDir() {
		printErrorAndExit(fmt.Errorf("%s: unable to download folder %s "+
			"on top of file", localBasePath, driveBasePath))
	}

	// Get the files from Drive under driveBasePath.
	includeBase := true
	message("Getting list of files to download... ")
	filesOnDrive, err := gd.GetFilesUnderFolder(driveBasePath, includeBase)
	checkFatalError(err, "error getting files from Drive")
	message("Done. Starting download.\n")

	// We won't download files where there are multiple versions of the
	// file with the same name on Drive.  Issue warnings about any dupes
	// here.
	uniqueDriveFiles, dupes := gdrive.PartitionUniquesAndMultiples(filesOnDrive)
	nDownloadErrors := int32(len(dupes))
	for _, f := range dupes {
		fmt.Fprintf(os.Stderr, "skicka: %s: skipping download of duplicate "+
			"file on Drive\n", f[0].Path)
	}

	// If we're not trying to download Google Apps files (Docs, etc.),
	// then filter them out here.
	if !downloadGoogleAppsFiles {
		var files []*gdrive.File
		for _, f := range uniqueDriveFiles {
			if f.IsGoogleAppsFile() {
				message("%s: skipping Google Apps file.", f.Path)
			} else {
				files = append(files, f)
			}
		}
		uniqueDriveFiles = files
	}

	// Create a map that stores the local filename to use for each file in
	// Google Drive. This map is indexed by the path of the Google Drive
	// file.
	localPathMap := createPathMap(uniqueDriveFiles, localBasePath, driveBasePath)

	// First create all of the local directories, so that the downloaded
	// files have somewhere to land.  For any already-existing directories,
	// update their permissions to match the permissions of the
	// corresponding folder on Drive.  Stop executing if there's an error;
	// we almost certainly can't successfully go on if we failed creating
	// some local direcotries.
	err = createLocalDirectories(localPathMap, uniqueDriveFiles)
	checkFatalError(err, "")

	// Now figure out which files actually need to be downloaded and
	// initialize filesToDownload with their corresponding gdrive.Files.
	nBytesToDownload := int64(0)
	var filesToDownload []*gdrive.File
	for _, f := range uniqueDriveFiles {
		if f.IsFolder() {
			// Folders were aready taken care of by createLocalDirectories().
			continue
		}

		localPath := localPathMap[f.Path]
		needsDownload, err := fileNeedsDownload(localPath, f, trustTimes)
		if err != nil {
			addErrorAndPrintMessage(&nDownloadErrors,
				fmt.Sprintf("%s: error determining if file needs download\n",
					f.Path), err)
			continue
		}

		if needsDownload {
			nBytesToDownload += f.FileSize
			filesToDownload = append(filesToDownload, f)
		} else {
			// No download needed, but make sure the local permissions and
			// modified time match those values on Drive.
			syncLocalFileMetadata(localPath, f, &nDownloadErrors)
		}
	}

	// Bail out early if everything is up to date.
	if len(filesToDownload) == 0 {
		message("Nothing to download.")
		return 0
	}

	// Actually download the files. We'll use multiple workers to improve
	// performance; we're more likely to have some workers actively
	// downloading file contents while others are still making Drive API
	// calls this way.
	toDownloadChan := make(chan *gdrive.File, 128)
	doneChan := make(chan int, nWorkers)
	progressBar := getProgressBar(nBytesToDownload)

	// Launch the workers.
	for i := 0; i < nWorkers; i++ {
		go func() {
			for {
				// Get the gdrive.File for the file the worker should download
				// next.
				if f, ok := <-toDownloadChan; ok {
					localPath := localPathMap[f.Path]
					err := downloadFile(f, localPath, progressBar)
					if err != nil {
						addErrorAndPrintMessage(&nDownloadErrors, localPath, err)
					}
				} else {
					debug.Printf("Worker exiting")
					doneChan <- 1
					break
				}
			}
		}()
	}

	// Send the workers the files to be downloaded.
	for _, f := range filesToDownload {
		toDownloadChan <- f
	}
	close(toDownloadChan)

	// And now wait for the workers to all return.
	for i := 0; i < nWorkers; i++ {
		<-doneChan
	}
	if progressBar != nil {
		progressBar.Finish()
	}

	if nDownloadErrors > 0 {
		fmt.Fprintf(os.Stderr, "skicka: %d files not downloaded due to errors\n",
			nDownloadErrors)
	}
	return int(nDownloadErrors)
}

func syncLocalFileMetadata(localPath string, f *gdrive.File, nDownloadErrors *int32) {
	mode, err := getPermissions(f)
	if err != nil {
		mode = 0644
	}
	if err := os.Chmod(localPath, mode); err != nil {
		addErrorAndPrintMessage(nDownloadErrors, localPath, err)
	}

	if err := os.Chtimes(localPath, normalizeModTime(f.ModTime), normalizeModTime(f.ModTime)); err != nil {
		addErrorAndPrintMessage(nDownloadErrors, localPath, err)
	}
}

// Create a map, indexed by Google Drive file Id, that gives the local
// pathname to use for the corresponding Google Drive file.
func createPathMap(files []*gdrive.File, localBasePath, driveBasePath string) map[string]string {
	if driveBasePath[0] == os.PathSeparator {
		if len(driveBasePath) > 1 {
			driveBasePath = driveBasePath[1:]
		} else {
			driveBasePath = ""
		}
	}

	m := make(map[string]string)
	for _, f := range files {
		localPath := localBasePath
		if !strings.HasPrefix(f.Path, driveBasePath) {
			panic(fmt.Sprintf("Drive path %s doesn't start with base path %s prefix!",
				f.Path, driveBasePath))
		}
		if len(f.Path) > len(driveBasePath) {
			localPath = path.Join(localPath, f.Path[len(driveBasePath):])
		}
		debug.Printf("Drive file %s [id %s] -> local %s", f.Path, f.Id, localPath)

		encrypted, _ := isEncrypted(f)
		if encrypted {
			localPath = strings.TrimSuffix(localPath, encryptionSuffix)
		}

		m[f.Path] = localPath
	}
	return m
}

func getProgressBar(nBytes int64) *pb.ProgressBar {
	if quiet {
		return nil
	}

	progressBar := pb.New64(nBytes).SetUnits(pb.U_BYTES)
	progressBar.ShowBar = true
	progressBar.Output = os.Stderr
	progressBar.Start()
	return progressBar
}

// Download a single file from Google Drive, saving it to the given path.
func downloadFile(f *gdrive.File, localPath string, progressBar *pb.ProgressBar) error {
	writeCloser, err := getLocalWriterForDriveFile(localPath, f)
	if err != nil {
		return err
	}
	defer writeCloser.Close()

	// Tee writes to the progress bar, which provides the Writer interface
	// and updates itself according to the number of bytes that it sees.
	var multiwriter io.Writer
	if progressBar != nil {
		multiwriter = io.MultiWriter(writeCloser, progressBar)
	} else {
		multiwriter = writeCloser
	}

	// FIXME: downloadDriveFile needs a name that better distinguishes its
	// function from downloadFile.
	if err := downloadDriveFile(multiwriter, f); err != nil {
		// Remove the incomplete file from the failed download.
		_ = os.Remove(localPath)
		return err
	}

	verbose.Printf("Downloaded and wrote %d bytes to %s", f.FileSize, localPath)

	return os.Chtimes(localPath, normalizeModTime(f.ModTime), normalizeModTime(f.ModTime))
}

// Create all of the directories on the local filesystem for the folders in
// the given array of gdrive.Files.
func createLocalDirectories(localPathMap map[string]string, files []*gdrive.File) error {
	for _, f := range files {
		if !f.IsFolder() {
			continue
		}

		permissions, err := getPermissions(f)
		if err != nil {
			// We may not have a permissions property if the file was
			// created directly via the Drive webpage.
			permissions = 0755
		}
		if permissions&0700 != 0700 {
			fmt.Fprintf(os.Stderr, "skicka: %s directory permissions %#o don't allow "+
				"writing. Using %#o permissions.\n", f.Path, permissions,
				permissions|0700)
			permissions |= 0700
		}

		dirPath := localPathMap[f.Path]
		if stat, err := os.Stat(dirPath); err == nil {
			// A file or directory already exists at dirPath.
			if !stat.IsDir() {
				return fmt.Errorf("%s: is a regular file but %s on Google Drive is a folder",
					dirPath, f.Path)
			}
		} else {
			// Create a local directory.
			verbose.Printf("Creating directory %s for %s with permissions %#o",
				dirPath, f.Path, permissions)
			err = os.Mkdir(dirPath, permissions)
			if err != nil {
				return err
			}
		}

		// In either case, update the directory's permissions to match
		// those of the file on Drive.  This is important both in case the
		// permissions changed on Drive as well as for the case of creating
		// a new directory: on Unix, the umask value affects the actual
		// permissions, while we'd really like to exactly match them.
		err = os.Chmod(dirPath, permissions)
		if err != nil {
			return err
		}
	}
	return nil
}

// If a file is encrypted, it should both have the initialization vector used
// to encrypt it stored as a Drive file property and have encryptionSuffix at the end
// of its filename. This function checks both of these and returns an error if
// these indicators are inconsistent; otherwise, it returns true/false
// accordingly.
func isEncrypted(file *gdrive.File) (bool, error) {
	if _, err := file.GetProperty("IV"); err == nil {
		if strings.HasSuffix(file.Path, encryptionSuffix) {
			return true, nil
		}
		return false, fmt.Errorf("has IV property but doesn't " +
			"end with .aes256 suffix")
	} else if strings.HasSuffix(file.Path, encryptionSuffix) {
		// This could actually happen with an interrupted upload
		// with 403 errors and the case where a file is created
		// even though a 403 happened, if we don't get to delete
		// the file before exiting...
		return false, fmt.Errorf("ends with .aes256 suffix but doesn't " +
			"have IV property")
	}
	return false, nil
}

// fileNeedsDownload returns true if the given gdrive.File is more recent
// than the corresponding local file (if any) and should be downloaded. It
// tries to do the inexpensive tests first, before going to the trouble of
// comparing file contents.
func fileNeedsDownload(localPath string, driveFile *gdrive.File,
	trustTimes bool) (bool, error) {
	// See if the local version of the file exists at all.
	stat, err := os.Stat(localPath)
	if err == os.ErrNotExist {
		// The local file doesn't exist. This is fine. Download it.
		debug.Printf("fileNeedsDownload: %s: doesn't exist. Downloading.", localPath)
		return true, nil
	} else if err != nil {
		// Some other error. Troubling, but go for the download and see if
		// things work out.
		debug.Printf("fileNeedsDownload: %s: %s. Downloading.", localPath, err)
		return true, nil
	}

	// Compare the local and Drive file sizes; if they don't match, we
	// definitely need to download.
	localSize := stat.Size()
	driveSize := driveFile.FileSize

	// Adjust driveSize for encrypted files to account for the
	// initialization vector being stored in the first aes.BlockSize bytes
	// of the file on Drive.
	encrypt, err := isEncrypted(driveFile)
	if err != nil {
		return false, err
	}
	if encrypt {
		driveSize -= aes.BlockSize
	}

	if localSize != driveSize {
		debug.Printf("fileNeedsDownload: size mismatch: local %s = %d, drive %s = %d",
			localPath, localSize, driveFile.Path, driveSize)
		return true, nil
	}

	driveModificationTime := normalizeModTime(driveFile.ModTime)
	localModificationTime := normalizeModTime(stat.ModTime())

	// If we're trusting modification times to be accurate (the default),
	// then if the sizes match (as above) and the modification times match,
	// we'll assume the file contents are the same.
	if trustTimes && localModificationTime.Equal(driveModificationTime) {
		return false, nil
	}

	// The file sizes are the same and either we're not trusting
	// modification times or the local file's modification time differs
	// from the Drive file.
	var iv []byte
	if encrypt {
		iv, err = getInitializationVector(driveFile)
		if err != nil {
			return false, fmt.Errorf("unable to get IV: %v", err)
		}
	}
	localMD5, err := localFileMD5Contents(localPath, encrypt, iv)
	if err != nil {
		return true, err
	}
	md5Mismatch := localMD5 != driveFile.Md5

	if !trustTimes && md5Mismatch && localModificationTime.Equal(driveModificationTime) {
		fmt.Fprintf(os.Stderr, "skicka: %s: local modification time matches "+
			"Google Drive file %s, but file contents differ!\n",
			localPath, driveFile.Path)
	}

	return md5Mismatch, nil
}

// Sync the given file from Google Drive to the local filesystem.
func downloadDriveFile(writer io.Writer, driveFile *gdrive.File) error {
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
			key = decryptEncryptionKey()
		}

		// Read the initialization vector from the start of the file.
		iv := make([]byte, 16)
		n, err := contentsReader.Read(iv)
		if err != nil && err != io.EOF {
			return err
		}
		if n < aes.BlockSize {
			return fmt.Errorf("contents too short to hold IV: %d bytes", n)
		}

		// Double check that the IV matches the one in the Drive metadata.
		ivp, err := getInitializationVector(driveFile)
		if err != nil {
			return err
		}
		if bytes.Compare(iv, ivp) != 0 {
			return fmt.Errorf("file start IV [%s] doesn't match properties IV [%s]",
				hex.EncodeToString(iv), hex.EncodeToString(ivp))
		}

		r = makeDecryptionReader(key, iv, r)
	}

	// Wrap the reader so that we can count how many bytes are read (in
	// case we error out in the middle of the download and don't read
	// everything.)
	bcr := &byteCountingReader{R: r}

	// And here's where the magic happens.
	_, err = io.Copy(writer, bcr)

	atomic.AddInt64(&stats.DownloadBytes, bcr.bytesRead)
	atomic.AddInt64(&stats.DiskWriteBytes, bcr.bytesRead)
	if err == nil {
		atomic.AddInt64(&stats.LocalFilesUpdated, 1)
	}

	return err
}

func getLocalWriterForDriveFile(localPath string,
	driveFile *gdrive.File) (io.WriteCloser, error) {
	// Remove the local file, if it exists.
	err := os.Remove(localPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// Create or overwrite the local file.
	f, err := os.Create(localPath)
	if err != nil {
		return nil, err
	}

	// Set the file's permissions to match the permissions on Drive.
	permissions, err := getPermissions(driveFile)
	if err != nil {
		permissions = 0644
	}
	err = os.Chmod(localPath, permissions)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
