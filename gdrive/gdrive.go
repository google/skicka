//
// gdrive.go
// Copyright(c)2014-2015 Google, Inc.
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

// Package gdrive provides a slightly higher-level API for Google Drive
// than is provided by the official Google Drive API Go language bindings.
// In addition to handling transient network errors, rate limit
// errors, and other http miscellania, gdrive also provides functionality
// for limiting bandwidth consumption in both uploads and downloads.
//
// gdrive was written to be independent of the skicka application; issues
// like encryption, mapping Google Drive files to Unix file semantics,
// etc., are intentionally not included here.
package gdrive

import (
	"code.google.com/p/goauth2/oauth"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/cheggaaa/pb"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/googleapi"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const timeFormat = "2006-01-02T15:04:05.000000000Z07:00"

///////////////////////////////////////////////////////////////////////////

// File represents a file or folder in Google Drive.
type File struct {
	Path       string
	FileSize   int64
	Id         string
	Md5        string
	MimeType   string
	ModTime    time.Time
	ParentIds  []string
	Properties []Property
}

func newFile(path string, f *drive.File) *File {
	modTime := time.Unix(0, 0)
	if f.ModifiedDate != "" {
		modTime, _ = time.Parse(time.RFC3339Nano, f.ModifiedDate)
	}

	var properties []Property
	for _, p := range f.Properties {
		properties = append(properties, Property{Key: p.Key, Value: p.Value})
	}

	var parentIds []string
	for _, p := range f.Parents {
		parentIds = append(parentIds, p.Id)
	}

	return &File{
		Path:       path,
		FileSize:   f.FileSize,
		Id:         f.Id,
		Md5:        f.Md5Checksum,
		MimeType:   f.MimeType,
		ModTime:    modTime,
		ParentIds:  parentIds,
		Properties: properties,
	}
}

// driveFile returns a new *drive.File that corresponds to the gdrive.File.
func (f *File) driveFile() *drive.File {
	var parents []*drive.ParentReference
	for _, pid := range f.ParentIds {
		parents = append(parents, &drive.ParentReference{Id: pid})
	}

	return &drive.File{
		Title:        filepath.Base(f.Path),
		FileSize:     f.FileSize,
		Id:           f.Id,
		Md5Checksum:  f.Md5,
		MimeType:     f.MimeType,
		ModifiedDate: f.ModTime.UTC().Format(timeFormat),
		Parents:      parents,
		Properties:   convertProplist(f.Properties),
	}
}

// IsFolder returns a boolean indicating whether the given File is a
// folder.
func (f *File) IsFolder() bool {
	return f.MimeType == "application/vnd.google-apps.folder"
}

// IsGoogleAppsFile returns a boolean indicating whether the given File was created
// with Google Docs, Google Sheets, etc.
func (f *File) IsGoogleAppsFile() bool {
	return strings.HasPrefix(f.MimeType, "application/vnd.google-apps.")
}

// Property represents a user-specified property associated with a Drive
// file.
type Property struct {
	Key, Value string
}

// GetProperty returns the property of the given name associated with the
// given file, if the named property is present.  If the property isn't
// present in the fie, then an empty string and an error are returned.
func (f *File) GetProperty(name string) (string, error) {
	for _, prop := range f.Properties {
		if prop.Key == name {
			return prop.Value, nil
		}
	}
	return "", fmt.Errorf("%s: property not found", name)
}

// Helper declarations to be able to sort an array of File values by
// pathname.
type byPath []*File

func (a byPath) Len() int           { return len(a) }
func (a byPath) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byPath) Less(i, j int) bool { return a[i].Path < a[j].Path }

///////////////////////////////////////////////////////////////////////////

var ErrNotExist = errors.New("file does not exist")
var ErrMultipleFiles = errors.New("multiple files on Drive")

///////////////////////////////////////////////////////////////////////////
// GDrive

// GDrive encapsulates a session for performing operations with Google
// Drive. It provides a variety of methods for working with files and
// folders stored in Google Drive.
type GDrive struct {
	oAuthTransport         *oauth.Transport
	svc                    *drive.Service
	debug                  func(s string, args ...interface{})
	uploadBytesPerSecond   int
	downloadBytesPerSecond int
	dirToFiles             map[string][]*File
	pathToFile             map[string][]*File
}

///////////////////////////////////////////////////////////////////////////
// Utility routines

const maxRetries = 6

// There are a number of cases where the Google Drive API returns an error
// code but where it's possible to recover from the error; examples include
// 401 errors when the OAuth2 token expires after an hour, or 403/500 errors
// when we make too many API calls too quickly and we get a rate limit error.
// This function takes an error returned by a Drive API call and the number
// of times that we've tried to call the API entrypoint already and does
// its best to handle the error.
//
// If it thinks the error may be transient, it returns nil, and the caller
// should try the call again. For unrecoverable errors (or putatively
// transient ones that don't clear up after multiple tries), it returns the
// error code back and the caller should stop trying.
func (gd *GDrive) tryToHandleDriveAPIError(err error, try int) error {
	gd.debug("tryToHandleDriveAPIError: try %d error %T %+v",
		try, err, err)

	if try == maxRetries {
		return err
	}
	switch err := err.(type) {
	case *googleapi.Error:
		if err.Code == 401 {
			// After an hour, the OAuth2 token expires and needs to
			// be refreshed.
			gd.debug("Trying OAuth2 token refresh.")
			if err := gd.oAuthTransport.Refresh(); err == nil {
				// Success
				return nil
			}
			// Otherwise fall through to sleep/backoff...
		}
	}

	gd.exponentialBackoff(try, nil, err)
	return nil
}

// getFileById returns the *drive.File corresponding to the string Id
// Google Drive uses to uniquely identify the file. It deals with timeouts
// and transient errors.
func (gd *GDrive) getFileById(id string) (*drive.File, error) {
	gd.debug("getFileById: %s", id)
	for try := 0; ; try++ {
		file, err := gd.svc.Files.Get(id).Do()
		if err == nil {
			return file, nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return nil, err
		}
	}
}

// runQuery executes the given query with the Google Drive API, returning
// an array of files that match the query's conditions.
func (gd *GDrive) runQuery(query string) ([]*drive.File, error) {
	gd.debug("Running query: %s", query)
	pageToken := ""
	var result []*drive.File
	for {
		q := gd.svc.Files.List().Q(query)
		if pageToken != "" {
			q = q.PageToken(pageToken)
		}

		for try := 0; ; try++ {
			r, err := q.Do()
			if err == nil {
				result = append(result, r.Items...)
				pageToken = r.NextPageToken
				break
			} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
				return nil, err
			}
		}

		if pageToken == "" {
			break
		}
	}
	return result, nil
}

///////////////////////////////////////////////////////////////////////////
// Public Interface

// New returns a pointer to a new GDrive instance. The clientid and
// clientsecret parameters are Google account credentials, and cacheFile is
// the path to a file that caches OAuth2 authorization tokens.
//
// The uploadBytesPerSecond and downloadBytesPerSecond parameters can be
// used to specify bandwidth limits if rate-limited uploads or downloads
// are desired.  If zero, bandwidth use is unconstrained.
//
// Finally, if debug is true, then debugging information will be printed as
// operations are performed.
func New(clientId, clientSecret, cacheFile string,
	uploadBytesPerSecond, downloadBytesPerSecond int,
	debug func(s string, args ...interface{}), transport http.RoundTripper,
	cacheFilename string) (*GDrive, error) {
	config := &oauth.Config{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Scope:        "https://www.googleapis.com/auth/drive",
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://accounts.google.com/o/oauth2/token",
		TokenCache:   oauth.CacheFile(cacheFile),
	}

	gd := GDrive{oAuthTransport: &oauth.Transport{
		Config: config,
	},
		debug:                  debug,
		uploadBytesPerSecond:   uploadBytesPerSecond,
		downloadBytesPerSecond: downloadBytesPerSecond,
	}

	gd.oAuthTransport.Transport = transport

	token, err := config.TokenCache.Token()
	if err != nil {
		authURL := config.AuthCodeURL("state")
		fmt.Printf("Go to the following link in your browser:\n%v\n", authURL)
		fmt.Printf("Enter verification code: ")
		var code string
		fmt.Scanln(&code)
		token, err = gd.oAuthTransport.Exchange(code)
		if err != nil {
			return nil, err
		}
	}
	gd.oAuthTransport.Token = token

	gd.svc, err = drive.New(gd.oAuthTransport.Client())
	if err != nil {
		return nil, err
	}

	gd.UpdateMetadataCache(cacheFilename)

	return &gd, err
}

func (gd *GDrive) updateCache(svc *drive.Service, maxChangeId int64,
	changeChan chan []*drive.Change) {
	var about *drive.About
	var err error

	for try := 0; try < maxRetries; try++ {
		about, err = svc.About.Get().Do()
		if err != nil {
			err = gd.tryToHandleDriveAPIError(err, try)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skicka: %s\n", err)
				os.Exit(1)
			}
		}
	}

	var bar *pb.ProgressBar
	if about.LargestChangeId-maxChangeId > 1000 {
		bar = pb.New64(about.LargestChangeId)
		bar.ShowBar = true
		bar.ShowCounters = false
		bar.Output = os.Stderr
		bar.Prefix("Updating metadata cache: ")
		bar.Start()
	}

	pageToken := ""
	try := 0
	for {
		q := svc.Changes.List().MaxResults(1000).IncludeSubscribed(false)
		q = q.Fields("nextPageToken",
			"items/id", "items/fileId", "items/deleted",
			"items/file/id", "items/file/parents", "items/file/title",
			"items/file/fileSize", "items/file/mimeType", "items/file/properties",
			"items/file/modifiedDate", "items/file/md5Checksum", "items/file/labels")
		if maxChangeId >= 0 {
			q = q.StartChangeId(maxChangeId + 1)
		}
		if pageToken != "" {
			q = q.PageToken(pageToken)
		}

		r, err := q.Do()
		if err != nil {
			err = gd.tryToHandleDriveAPIError(err, try)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skicka: %s\n", err)
				os.Exit(1)
			}
			try++
			continue
		} else {
			try = 0
		}

		changeChan <- r.Items

		if len(r.Items) == 0 {
			break
		}

		if bar != nil {
			bar.Set(int(r.Items[len(r.Items)-1].Id))
		}

		pageToken = string(r.NextPageToken)
		if pageToken == "" {
			break
		}
	}
	changeChan <- []*drive.Change{}

	if bar != nil {
		bar.Finish()
	}

	gd.debug("done updating from drive %s", time.Now().String())
}

// saveMetadataCache saves both the current maximum change id as well as
// the mapping from Drive file id's to *drive.File objects into the given
// file.
func (gd *GDrive) saveMetadataCache(filename string, maxChangeId int64,
	m map[string]*File) {
	// Save the information into a temporary file; when we're done, we'll
	// rename this to the destination filename.  This ensures that the
	// update is atomic and we don't accidentally write a partial file if
	// we're interrupted.
	f, err := ioutil.TempFile("", "skicka.metadata")
	if err != nil {
		panic(err)
	}

	e := gob.NewEncoder(f)
	version := 1
	// First goes the metadata verion number.
	if err := e.Encode(version); err == nil {
		// Then goes the current change id from Drive.
		if err := e.Encode(maxChangeId); err == nil {
			// Next goes the serialized map from strings to File structures.
			if err = e.Encode(m); err == nil {
				// Make sure it has all successfully landed on disk.
				if err = f.Sync(); err == nil {
					if err = f.Close(); err == nil {
						// And now rename the temporary file to the actual
						// cache filename; this ensures that we have an atomic
						// update and don't inadvertently write out a truncated
						// file if there's an error.
						err = os.Rename(f.Name(), filename)
					}
				}
			}
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "skicka: %s: error saving file cache: %s\n",
			filename, err)
	} else {
		gd.debug("Done writing new file cache to disk %s", time.Now().String())
	}
}

// UpdateMetadataCache initializes the local cache of metadata about the files and folders
// currently on Google Drive; if some information is
func (gd *GDrive) UpdateMetadataCache(filename string) {
	if runtime.GOOS != "windows" {
		if stat, err := os.Stat(filename); err == nil {
			perms := stat.Mode() & ((1 << 6) - 1)
			if perms != 0 {
				fmt.Fprintf(os.Stderr, "skicka: %s: permissions allow group/other "+
					"access. Metadata of your Drive files is accessible by others.",
					filename)
			}
		}
	}

	maxChangeId := int64(-1)

	f, err := os.Open(filename)
	changeChan := make(chan []*drive.Change, 32)
	idToFile := make(map[string]*File)
	if err == nil {
		defer f.Close()
		decoder := gob.NewDecoder(f)

		var version int
		decoder.Decode(&version)
		if version != 1 {
			fmt.Fprintf(os.Stderr, "skicka: metadata file version %d unknown to "+
				"this version of skicka", version)
			os.Exit(1)
		}

		decoder.Decode(&maxChangeId)
		gd.debug("Read max change id %d\n", maxChangeId)

		go gd.updateCache(gd.svc, maxChangeId, changeChan)

		decoder.Decode(&idToFile)
		gd.debug("Done reading file cache from disk @ %s\n", time.Now().String())
	} else {
		go gd.updateCache(gd.svc, maxChangeId, changeChan)
	}

	newMaxChangeId := maxChangeId
	for {
		changes := <-changeChan
		if len(changes) == 0 {
			break
		}

		for _, c := range changes {
			if c.Id < newMaxChangeId {
				panic(fmt.Sprintf("Change id %d less than max %d!", c.Id, newMaxChangeId))
			}
			newMaxChangeId = c.Id

			if c.Deleted || (c.File != nil && c.File.Labels != nil && c.File.Labels.Trashed) {
				if _, ok := idToFile[c.FileId]; ok {
					delete(idToFile, c.FileId)
				}
			} else {
				idToFile[c.File.Id] = newFile(c.File.Title, c.File)
			}
		}
	}
	gd.debug("File cache has %d items\n", len(idToFile))

	if newMaxChangeId > maxChangeId {
		gd.debug("Writing updated file cache to disk: maxChangeId now %d\n",
			newMaxChangeId)
		gd.saveMetadataCache(filename, newMaxChangeId, idToFile)
	}

	// convert map from id -> File to a map from parent folder path ->
	// array of Files in the folder.
	gd.dirToFiles = make(map[string][]*File)
	gd.pathToFile = make(map[string][]*File)

	rootDriveFile, err := gd.getFileById("root")
	if err != nil {
		panic(err)
	}
	rootFile := newFile(string(os.PathSeparator), rootDriveFile)
	gd.pathToFile[rootFile.Path] = append(gd.pathToFile[rootFile.Path], rootFile)

	for _, file := range idToFile {
		var paths []string
		for _, pid := range file.ParentIds {
			getPath(filepath.Base(file.Path), pid, idToFile, &paths)
		}
		for _, p := range paths {
			f := file
			f.Path = p
			gd.pathToFile[p] = append(gd.pathToFile[p], f)

			dir := filepath.Dir(p)
			if dir == "." {
				dir = string(os.PathSeparator)
			}
			gd.dirToFiles[dir] = append(gd.dirToFiles[dir], f)
		}
	}
}

func getPath(p string, parentId string, idToFile map[string]*File, paths *[]string) {
	parentFile, ok := idToFile[parentId]
	if !ok {
		*paths = append(*paths, p)
	} else {
		for _, ppid := range parentFile.ParentIds {
			newp := filepath.Join(filepath.Base(parentFile.Path), p)
			getPath(newp, ppid, idToFile, paths)
		}
	}
}

// GetFile returns the File corresponding to a file or folder specified by
// the given path starting from the root of the Google Drive filesystem.
// (Note that File is used to represent both files and folders in Google
// Drive.)
func (gd *GDrive) GetFile(path string) (*File, error) {
	path = cleanPath(path)
	files, ok := gd.pathToFile[path]
	if !ok {
		return nil, ErrNotExist
	} else if len(files) > 1 {
		return nil, ErrMultipleFiles
	}
	return files[0], nil
}

func cleanPath(path string) string {
	path = filepath.Clean(path)
	if path == "." {
		path = string(os.PathSeparator)
	} else if len(path) > 1 && path[0] == os.PathSeparator {
		path = path[1:]
	}
	return path
}

// GetFiles returns File structures for *all* of the files in Google Drive
// that correspond to the given path. Because Google Drive allows multiple
// files to have the same title (and allows multiple folders of the same
// name), this is more complicated than it might seen.
//
// Note: an error is not returned if the file doesn't exist; the caller
// should detect that case by detecting a zero-length returned array for
// that case.
func (gd *GDrive) GetFiles(path string) []*File {
	path = cleanPath(path)
	var files []*File
	if path == string(os.PathSeparator) {
		files = append(files, gd.pathToFile[path][0])
	} else {
		d := filepath.Dir(path)
		if d == "." {
			d = "/"
		}
		for _, f := range gd.dirToFiles[d] {
			if filepath.Base(f.Path) == filepath.Base(path) {
				files = append(files, f)
			}
		}
	}
	return files
}

// GetFilesInFolder returns a Files object representing the files in the
// given folder with the given name.
func (gd *GDrive) GetFilesInFolder(path string) (Files, error) {
	files := newFiles()
	dirFiles, ok := gd.dirToFiles[cleanPath(path)]
	if !ok {
		return files, ErrNotExist
	}

	for _, f := range dirFiles {
		files.add(f)
	}
	return files, nil
}

// Files represents a cached mapping between pathnames and files stored in
// Google Drive.
type Files struct {
	files map[string][]*File
}

func newFiles() Files {
	var f Files
	f.files = make(map[string][]*File)
	return f
}

// Add takes a pathname and a File and records that the given file lives at
// the given path in Google Drive.
func (f Files) add(file *File) {
	if file.Path != cleanPath(file.Path) {
		panic(fmt.Sprintf("unclean path: %s", file.Path))
	}

	f.files[file.Path] = append(f.files[file.Path], file)
}

// GetSorted returns a array of File structures, one for each Google Drive
// file represented by the Files object.  The array is sorted by the files
// pathnames.
func (f Files) GetSorted() []*File {
	var files []*File
	for _, fileArray := range f.files {
		for _, f := range fileArray {
			files = append(files, f)
		}
	}
	sort.Sort(byPath(files))
	return files
}

// GetSortedUnique sorts all of the files by path name and then returns two
// arrays of File structures.  The first includes all unique files--ones
// that only have a single file with that pathname on Drive.  The second has
// all files where there are two or more files with that name on Drive.
func (f Files) GetSortedUnique() ([]*File, map[string][]*File) {
	allFiles := f.GetSorted()

	var files []*File
	dupes := make(map[string][]*File)
	for i, f := range allFiles {
		// Non-duplicated files are different than their neighbors on both
		// sides (if present).
		if (i == 0 || f.Path != allFiles[i-1].Path) &&
			(i == len(allFiles)-1 || f.Path != allFiles[i+1].Path) {
			files = append(files, f)
		} else {
			dupes[f.Path] = append(dupes[f.Path], f)
		}
	}

	return files, dupes
}

// GetFilesUnderFolder returns a Files object that represents all of the
// files stored in GoogleDrive under the given path.  The 'includeBase'
// parameter indicates whether the file corresponding to the given path's
// folder should be included.
func (gd *GDrive) GetFilesUnderFolder(path string, includeBase bool) (Files, error) {
	files := newFiles()

	// Start by getting the file or files that correspond to the given
	// path.
	pathfiles := gd.GetFiles(path)
	if len(pathfiles) == 0 {
		return files, ErrNotExist
	}

	for _, f := range pathfiles {
		if f.IsFolder() {
			if includeBase {
				files.add(f)
			}
			gd.getFolderContentsRecursive(f, &files)
		} else {
			files.add(f)
		}
	}
	return files, nil
}

func (gd *GDrive) getFolderContentsRecursive(parentFolder *File, files *Files) {
	for _, f := range gd.dirToFiles[parentFolder.Path] {
		files.add(f)
		if f.IsFolder() {
			gd.getFolderContentsRecursive(f, files)
		}
	}
}

// GetFileContents returns an io.ReadCloser that provides the contents of
// the given File.
func (gd *GDrive) GetFileContents(f *File) (io.ReadCloser, error) {
	// The file download URL expires some hours after it's retrieved;
	// re-grab the file right before downloading it so that we have a
	// fresh URL.
	driveFile, err := gd.getFileById(f.Id)
	if err != nil {
		return nil, err
	}

	url := driveFile.DownloadUrl
	if url == "" {
		// Google Docs files can't be downloaded directly via DownloadUrl,
		// but can be exported to another format that can be downloaded.
		url = driveFile.ExportLinks[driveFile.MimeType]
	}

	for try := 0; ; try++ {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := gd.oAuthTransport.RoundTrip(request)

		switch gd.handleHTTPResponse(resp, err, try) {
		case Success:
			// Rate-limit the download, if required.
			if gd.downloadBytesPerSecond > 0 {
				launchBandwidthTask(gd.downloadBytesPerSecond)
				return rateLimitedReader{R: resp.Body}, nil
			}
			return resp.Body, nil
		case Fail:
			return nil, err
		case Retry:
		}
	}
}

// UpdateProperty updates the property with name 'name' to 'value' in
// the given file on Google Drive.
func (gd *GDrive) UpdateProperty(f *File, key string, value string) error {
	for _, prop := range f.Properties {
		if prop.Key == key {
			if prop.Value == value {
				// Save the network round-trip and return, since the
				// property already has the desired value.
				return nil
			}
			break
		}
	}

	// Update the file on Drive.
	prop := &drive.Property{Key: key, Value: value}

	for try := 0; ; try++ {
		_, err := gd.svc.Properties.Update(f.Id, key, prop).Do()
		if err == nil {
			// Success.
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return err
		}
	}
}

// UpdateModificationTime updates the modification time of the given Google
// Drive file to the given time.
func (gd *GDrive) UpdateModificationTime(f *File, newTime time.Time) error {
	gd.debug("updating modification time of %s to %v", f.Path, newTime)

	if f.ModTime.Equal(newTime) {
		return nil
	}

	for try := 0; ; try++ {
		fp := &drive.File{ModifiedDate: newTime.UTC().Format(timeFormat)}
		_, err := gd.svc.Files.Patch(f.Id, fp).SetModifiedDate(true).Do()
		if err == nil {
			gd.debug("success: updated modification time on %s", f.Path)
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return err
		}
	}
}

// AddProperty adds the property with given key and value to the provided
// file and updates the file in Google Drive.
func (gd *GDrive) AddProperty(key, value string, f *File) error {
	prop := &drive.Property{Key: key, Value: value}

	for try := 0; ; try++ {
		_, err := gd.svc.Properties.Insert(f.Id, prop).Do()
		if err == nil {
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return fmt.Errorf("unable to create %s property: %v",
				prop.Key, err)
		}
	}
}

// http://stackoverflow.com/questions/18578768/403-rate-limit-on-insert-sometimes-succeeds
// Sometimes when we get a 403 error from Files.Insert().Do(), a file is
// actually created. Delete the file to be sure we don't have duplicate
// files with the same name.
func (gd *GDrive) deleteIncompleteDriveFiles(title string, parentId string) {
	query := fmt.Sprintf("title='%s' and '%s' in parents and trashed=false",
		title, parentId)
	files, err := gd.runQuery(query)
	if err != nil {
		gd.debug("unable to run query in deleteIncompleteDriveFiles(); "+
			"ignoring error: %v", err)
		return
	}

	for _, f := range files {
		for try := 0; ; try++ {
			err := gd.svc.Files.Delete(f.Id).Do()
			if err == nil {
				break
			} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
				log.Fatalf("error deleting 403 Google Drive file "+
					"for %s (ID %s): %v", title, f.Id, err)
			}
		}
	}
}

func convertProplist(p []Property) []*drive.Property {
	var pl []*drive.Property
	for _, prop := range p {
		pl = append(pl, &drive.Property{Key: prop.Key, Value: prop.Value})
	}
	return pl
}

// CreateFile creates an actual file in Google Drive with the given
// filename.  The new file is in the folder given by represented by the
// 'parent' parameter, is initialized to have the given modification time
// and the provided Google Drive file properties.  The returned File value
// represents the file in Drive.
func (gd *GDrive) CreateFile(name string, parent *File,
	modTime time.Time, proplist []Property) (*File, error) {
	path := cleanPath(filepath.Join(parent.Path, name))
	if _, ok := gd.pathToFile[path]; ok {
		panic(fmt.Sprintf("%s: already exists!", path))
	}

	pr := &drive.ParentReference{Id: parent.Id}
	f := &drive.File{
		Title:        name,
		MimeType:     "application/octet-stream",
		Parents:      []*drive.ParentReference{pr},
		ModifiedDate: modTime.UTC().Format(timeFormat),
		Properties:   convertProplist(proplist),
	}
	f, err := gd.insertFile(f)
	if err != nil {
		return nil, err
	}

	return gd.updateCacheForNewFile(f, parent), nil
}

// CreateFolder creates a new folder in Google Drive with given name.
func (gd *GDrive) CreateFolder(name string, parent *File,
	modTime time.Time, proplist []Property) (*File, error) {
	path := cleanPath(filepath.Join(parent.Path, name))
	if _, ok := gd.pathToFile[path]; ok {
		panic(fmt.Sprintf("%s: already exists!", path))
	}

	pr := &drive.ParentReference{Id: parent.Id}
	f := &drive.File{
		Title:        name,
		MimeType:     "application/vnd.google-apps.folder",
		ModifiedDate: modTime.UTC().Format(timeFormat),
		Parents:      []*drive.ParentReference{pr},
		Properties:   convertProplist(proplist),
	}
	f, err := gd.insertFile(f)
	if err != nil {
		return nil, err
	}

	return gd.updateCacheForNewFile(f, parent), nil
}

func (gd *GDrive) updateCacheForNewFile(f *drive.File, parent *File) *File {
	file := newFile(cleanPath(filepath.Join(parent.Path, f.Title)), f)

	// Update the pathToFile map.
	switch len(gd.pathToFile[file.Path]) {
	case 0:
		gd.debug("%s: doesn't exist in path2file", file.Path)
		gd.pathToFile[file.Path] = append(gd.pathToFile[file.Path], file)
	case 1:
		gd.debug("%s: already exist in path2file", file.Path)
		gd.pathToFile[file.Path][0] = file
	default:
		panic("shouldn't be intentionally creating when have a file there already")
	}

	// Also update the parent folder's list of files, either replacing a
	// current instance of a file with this name or adding a new file for
	// this one.
	for i, dirFile := range gd.dirToFiles[parent.Path] {
		if dirFile.Path == file.Path {
			gd.debug("%s: already exists in dir2files", file.Path)
			gd.dirToFiles[parent.Path][i] = file
			return file
		}
	}

	gd.debug("%s: doesn't exist in dir2files", file.Path)
	gd.dirToFiles[parent.Path] = append(gd.dirToFiles[parent.Path], file)
	return file
}

func (gd *GDrive) insertFile(f *drive.File) (*drive.File, error) {
	for try := 0; ; try++ {
		r, err := gd.svc.Files.Insert(f).Do()
		if err == nil {
			gd.debug("Created new Google Drive file for %s: ID=%s",
				f.Title, r.Id)
			return r, nil
		}
		gd.debug("Error %v trying to create drive file for %s. "+
			"Deleting detrius...", err, f.Title)
		gd.deleteIncompleteDriveFiles(f.Title, f.Parents[0].Id)
		err = gd.tryToHandleDriveAPIError(err, try)
		if err != nil {
			return nil, fmt.Errorf("unable to create drive.File: %v", err)
		}
	}
}

// DeleteFile deletes the given file from Google Drive; note that delection
// is permanent and un-reversable!  (Consider TrashFile instead.)
func (gd *GDrive) DeleteFile(f *File) error {
	for try := 0; ; try++ {
		err := gd.svc.Files.Delete(f.Id).Do()
		if err == nil {
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return fmt.Errorf("unable to delete file %s: %v", f.Path, err)
		}
	}
}

// TrashFile moves the given Google Drive file to the trash; it is not
// immediately deleted permanently.
func (gd *GDrive) TrashFile(f *File) error {
	for try := 0; ; try++ {
		_, err := gd.svc.Files.Trash(f.Id).Do()
		if err == nil {
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return fmt.Errorf("unable to trash file %s: %v", f.Path, err)
		}
	}
}
