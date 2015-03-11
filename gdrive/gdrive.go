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
	"bytes"
	"code.google.com/p/goauth2/oauth"
	"errors"
	"fmt"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/googleapi"
	"io"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const timeFormat = "2006-01-02T15:04:05.000000000Z07:00"

///////////////////////////////////////////////////////////////////////////

var ErrNotExist = errors.New("file does not exist")
var ErrMultipleFiles = errors.New("multiple files on Drive")

// RetryHTTPTransmitError is a small struct to let us detect error cases
// where the caller should retry the operation, as the error seems to be a
// transient HTTP issue.
type RetryHTTPTransmitError struct {
	StatusCode int
	StatusBody string
}

func (r RetryHTTPTransmitError) Error() string {
	return fmt.Sprintf("http %d error (%s); retry", r.StatusCode, r.StatusBody)
}

///////////////////////////////////////////////////////////////////////////
// Bandwidth-limiting io.Reader

// Maximum number of bytes of data that we are currently allowed to
// upload or download given the bandwidth limits set by the user, if any.
// This value is reduced by the rateLimitedReader.Read() method when data is
// uploaded or downloaded, and is periodically increased by the task
// launched by launchBandwidthTask().
var availableTransmitBytes int
var bandwidthTaskRunning bool

// Mutex to protect availableTransmitBytes.
var bandwidthMutex sync.Mutex
var bandwidthCond = sync.NewCond(&bandwidthMutex)

func launchBandwidthTask(bytesPerSecond int) {
	if bytesPerSecond == 0 {
		// No limit, so no need to launch the task.
		return
	}

	bandwidthMutex.Lock()
	defer bandwidthMutex.Unlock()
	if bandwidthTaskRunning {
		return
	} else {
		bandwidthTaskRunning = true
	}

	go func() {
		for {
			bandwidthMutex.Lock()

			// Release 1/8th of the per-second limit every 8th of a second.
			// The 92/100 factor in the amount released adds some slop to
			// account for TCP/IP overhead in an effort to have the actual
			// bandwidth used not exceed the desired limit.
			availableTransmitBytes += bytesPerSecond * 92 / 100 / 8
			if availableTransmitBytes > bytesPerSecond {
				// Don't ever queue up more than one second's worth of
				// transmission.
				availableTransmitBytes = bytesPerSecond
			}

			// Wake up any threads that are waiting for more bandwidth now
			// that we've doled some more out.
			bandwidthCond.Broadcast()
			bandwidthMutex.Unlock()

			// Note that if the system is heavily loaded, it may be much
			// more than 1/8 of a second before the thread runs again, in
			// which case, the full second's bandwidth allotment won't be
			// released. We could instead track how much time has passed
			// between the last sleep and the following wakeup and adjust
			// the amount of bandwidth released accordingly if this turned
			// out to be an issue in practice.
			time.Sleep(time.Duration(125) * time.Millisecond)
		}
	}()
}

// rateLimitedReader is an io.Reader implementation that returns no more
// bytes than the current value of availableTransmitBytes.  Thus, as long
// as the upload and download paths wrap the underlying io.Readers for
// local files and GETs from Drive (respectively), then we should stay
// under the bandwidth per second limit.
type rateLimitedReader struct {
	R io.ReadCloser
}

func (lr rateLimitedReader) Read(dst []byte) (int, error) {
	// Loop until some amount of bandwidth is available.
	bandwidthMutex.Lock()
	for {
		if availableTransmitBytes < 0 {
			panic("bandwidth budget went negative")
		}
		if availableTransmitBytes > 0 {
			break
		}

		// No further uploading is possible at the moment; wait for the
		// thread that periodically doles out more bandwidth to do its
		// thing, at which point it will signal the condition variable.
		bandwidthCond.Wait()
	}

	// The caller would like us to return up to this many bytes...
	n := len(dst)

	// but don't try to upload more than we're allowed to...
	if n > availableTransmitBytes {
		n = availableTransmitBytes
	}

	// Update the budget for the maximum amount of what we may consume and
	// relinquish the lock so that other workers can claim bandwidth.
	availableTransmitBytes -= n
	bandwidthMutex.Unlock()

	read, err := lr.R.Read(dst[:n])
	if read < n {
		// It may turn out that the amount we read from the original
		// io.Reader is less than the caller asked for; in this case,
		// we give back the bandwidth that we reserved but didn't use.
		bandwidthMutex.Lock()
		availableTransmitBytes += n - read
		bandwidthMutex.Unlock()
	}

	return read, err
}

func (lr rateLimitedReader) Close() error {
	return lr.R.Close()
}

///////////////////////////////////////////////////////////////////////////

// somewhatSeekableReader is an io.Reader that can seek backwards from the
// current offset up to 'bufSize' bytes. It's useful for chunked file
// uploads, where we may need to rewind a bit after a failed chunk, but
// definitely don't want to pay the overhead of having the entire file in
// memory to be able to rewind arbitrarily for.
//
// It is implemented as a ring-buffer: the current offset in buf to read
// from is in readOffset, and the currentOffset to copy values read from
// the reader to is in writeOffset.  Both of these are taken mod bufSize
// when used to compute offsets into buf.
type somewhatSeekableReader struct {
	R                       io.Reader
	buf                     []byte
	readOffset, writeOffset int64
}

func makeSomewhatSeekableReader(r io.Reader, maxSeek int) *somewhatSeekableReader {
	return &somewhatSeekableReader{
		R:           r,
		buf:         make([]byte, maxSeek),
		readOffset:  0,
		writeOffset: 0,
	}
}

func (ssr *somewhatSeekableReader) Read(b []byte) (int, error) {
	// If the caller has called Seek() to move backwards from the
	// current read point of the underlying reader R, we start by
	// copying values from our local buffer into the output buffer.
	nCopied := 0
	if ssr.readOffset < ssr.writeOffset {
		for ; ssr.readOffset < ssr.writeOffset && nCopied < len(b); nCopied++ {
			b[nCopied] = ssr.buf[ssr.readOffset%int64(len(ssr.buf))]
			ssr.readOffset++
		}
	}

	// Once we're through the values we have buffered from previous reads,
	// we read from the underlying reader. Note that we read into b[]
	// starting at the point where we stopped copying buffered values.
	nRead, err := ssr.R.Read(b[nCopied:])

	// Now update our local buffer of read values.  Note that this loop
	// is a bit wasteful in the case where nRead > len(ssr.buf); some of
	// the values it writes will be clobbered by a later iteration of
	// the loop.  (It's not clear that this is a big enough issue to
	// really worry about.)
	for i := 0; i < nRead; i++ {
		ssr.buf[ssr.writeOffset%int64(len(ssr.buf))] = b[nCopied+i]
		ssr.readOffset++
		ssr.writeOffset++
	}

	return nCopied + nRead, err
}

func (ssr *somewhatSeekableReader) SeekTo(offset int64) error {
	if offset > ssr.writeOffset {
		// We could support seeking past the extent that the file has been
		// read (by just doing a bunch of Read() calls), but this isn't
		// really necessary currently...
		return fmt.Errorf("invalid seek to %d, past current write offset %d",
			offset, ssr.writeOffset)
	}
	if ssr.writeOffset-offset > int64(len(ssr.buf)) {
		return fmt.Errorf("can't seek back to %d; current offset %d",
			offset, ssr.writeOffset)
	}
	ssr.readOffset = offset
	return nil
}

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

func (gd *GDrive) exponentialBackoff(try int, resp *http.Response, err error) {
	s := time.Duration(1<<uint(try))*time.Second +
		time.Duration(mathrand.Int()%1000)*time.Millisecond
	time.Sleep(s)
	if resp != nil {
		gd.debug("exponential backoff: slept %v for resp %d...", s,
			resp.StatusCode)
	} else {
		gd.debug("exponential backoff: slept %v for error %v...", s, err)
	}
}

// getFileById returns the *drive.File corresponding to the string Id
// Google Drive uses to uniquely identify the file. It deals with timeouts
// and transient errors.
func (gd *GDrive) getFileById(id string) (*drive.File, error) {
	gd.debug("GetFileById: %s", id)
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

type HTTPResponseResult int

const (
	Success    HTTPResponseResult = iota
	Retry                         = iota
	Fail                          = iota
	RefreshURI                    = iota
)

// We've gotten an *http.Response (maybe) and an error (maybe) back after
// performing some HTTP operation; this function takes care of figuring
// out if the operation succeeded, refreshes OAuth2 tokens if expiration
// was the cause of the failure, takes care of exponential back-off for
// transient errors, etc.  It then returns a HTTPResponseResult to the
// caller, indicating how it should proceed.
func (gd *GDrive) handleHTTPResponse(resp *http.Response, err error,
	try int) HTTPResponseResult {
	if err == nil && resp != nil && resp.StatusCode >= 200 &&
		resp.StatusCode <= 299 {
		return Success
	}

	if try == maxRetries {
		return Fail
	}

	if resp != nil && resp.StatusCode == 401 {
		// After an hour, the OAuth2 token expires and needs to
		// be refreshed.
		gd.debug("Trying OAuth2 token refresh.")
		if err = gd.oAuthTransport.Refresh(); err == nil {
			// Success
			return Retry
		}
		// Otherwise fall through to sleep
	}

	// 403, 500, and 503 error codes come up for transient issues like
	// hitting the rate limit for Drive SDK API calls, but sometimes we get
	// other timeouts/connection resets here. Therefore, for all errors, we
	// sleep (with exponential backoff) and try again a few times before
	// giving up.
	gd.exponentialBackoff(try, resp, err)
	return Retry
}

type addKeyTransport struct {
	transport http.RoundTripper
	key       string
}

func (akt addKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.RawQuery != "" {
		req.URL.RawQuery += "&"
	}
	req.URL.RawQuery += "key=" + akt.key
	return akt.transport.RoundTrip(req)
}

type loggingTransport struct {
	transport http.RoundTripper
	gd        *GDrive
}

func (lt loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	dump, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		// Don't report an error back from RoundTrip() just because
		// DumpRequestOut() ran into trouble.
		lt.gd.debug("error dumping http request: %v", err)
	}

	resp, err := lt.transport.RoundTrip(req)
	lt.gd.debug("http request: %s   --> response: %+v\nerr: %v\n--------\n",
		dump, resp, err)
	return resp, err
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
func New(clientId, clientSecret, apiKey, cacheFile string,
	uploadBytesPerSecond, downloadBytesPerSecond int,
	debug func(s string, args ...interface{}), dumpHttp bool) (*GDrive, error) {
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

	transport := http.DefaultTransport
	if dumpHttp {
		transport = loggingTransport{transport: transport, gd: &gd}
	}
	if apiKey != "" {
		transport = addKeyTransport{transport: transport, key: apiKey}
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
	return &gd, err
}

// AddProperty adds the property with given key and value to the provided
// file and updates the file in Google Drive.
func (gd *GDrive) AddProperty(key, value string, f *drive.File) error {
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

// GetProperty returns the property of the given name associated with the
// given file, if the named property is present.  If the property isn't
// present in the fie, then an empty string and an error are returned.
func GetProperty(f *drive.File, name string) (string, error) {
	for _, prop := range f.Properties {
		if prop.Key == name {
			return prop.Value, nil
		}
	}
	return "", fmt.Errorf("%s: property not found", name)
}

// GetFile returns the *drive.File corresponding to a file or folder
// specified by the given path starting from the root of the Google Drive
// filesystem.  (Note that *drive.File is used to represent both files and
// folders in Google Drive.)
func (gd *GDrive) GetFile(path string) (*drive.File, error) {
	parent, err := gd.getFileById("root")
	if err != nil {
		return nil, fmt.Errorf("unable to get Drive root directory: %v", err)
	}

	dirs := strings.Split(path, "/")
	// Walk through the directories in the path in turn.
	for _, dir := range dirs {
		if dir == "" {
			// The first string in the split is "" if the
			// path starts with a '/'.
			continue
		}

		file, err := gd.GetFileInFolder(dir, parent)
		if err != nil {
			return nil, err
		}
		parent = file
	}
	return parent, nil
}

// GetFiles returns drive.File pointers for *all* of the files in Google
// Drive that correspond to the given path. Because Google Drive allows
// multiple files to have the same title (and allows multiple folders of
// the same name), this is more complicated than it might seen.
//
// Note: an error is not returned if the file doesn't exist; the caller
// should detect that case by detecting a zero-length returned array for
// that case.
func (gd *GDrive) GetFiles(path string) ([]*drive.File, error) {
	root, err := gd.getFileById("root")
	if err != nil {
		return nil, fmt.Errorf("unable to get Drive root directory: %v", err)
	}
	// Special case the root directory.
	if path == "/" {
		files := make([]*drive.File, 1)
		files[0] = root
		return files, nil
	}

	components := strings.Split(path, "/")
	if components[0] == "" {
		// The first string in the split is "" if the path starts with a
		// '/', so skip over that directory component.
		components = components[1:]
	}
	var files []*drive.File
	err = gd.getFilesRecursive(components, root, &files)
	return files, err
}

// Given an array of components of a path relative to the given parent
// folder, return all of the files under the parent that correspond to the
// given path.
func (gd *GDrive) getFilesRecursive(components []string, parent *drive.File,
	files *[]*drive.File) error {
	if len(components) == 0 {
		return nil
	}

	query := fmt.Sprintf("title='%s' and '%s' in parents and trashed=false",
		components[0], parent.Id)
	dirfiles, err := gd.runQuery(query)
	if err != nil {
		return err
	}

	for _, f := range dirfiles {
		if len(components) == 1 {
			// We've reached the last component of the path, so have
			// finally found a matching file.
			*files = append(*files, f)
		} else {
			err = gd.getFilesRecursive(components[1:], f, files)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// GetFilesInFolder returns an array of *drive.File values, one for each
// file in the given folder with the given name.
func (gd *GDrive) GetFilesInFolder(name string, folder *drive.File) ([]*drive.File, error) {
	query := fmt.Sprintf("title='%s' and '%s' in parents and trashed=false",
		name, folder.Id)
	files, err := gd.runQuery(query)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, ErrNotExist
	}
	return files, nil
}

// GetFileInFolder returns a single *drive.File for the given filename in
// the given folder.  An error is returned if multiple files in that folder
// all have the same name.
func (gd *GDrive) GetFileInFolder(name string, folder *drive.File) (*drive.File, error) {
	files, err := gd.GetFilesInFolder(name, folder)
	if err != nil {
		return nil, err
	} else if len(files) > 1 {
		return nil, ErrMultipleFiles
	}
	return files[0], nil
}

// Files represents a cached mapping between pathnames and files stored in
// Google Drive.
type Files struct {
	files map[string][]*drive.File
}

func newFiles() Files {
	var f Files
	f.files = make(map[string][]*drive.File)
	return f
}

// Add takes a pathname and a *drive.File and records that the given file
// lives at the given path in Google Drive.
func (f Files) Add(path string, df *drive.File) {
	f.files[path] = append(f.files[path], df)
}

// GetOne returns a single *drive.File for the given path, if a file with
// that name exists on Google Drive.  It returns the error ErrNotExist if
// no such file exists, and ErrMultipleFiles if multiple files with that
// pathname exist.
func (f Files) GetOne(path string) (*drive.File, error) {
	fs, ok := f.files[path]
	if !ok {
		return nil, ErrNotExist
	} else if len(fs) > 1 {
		return nil, ErrMultipleFiles
	}
	return fs[0], nil
}

// Get returns all of the *drive.Files that are named by the given path.
// If no such file exists, it returns the ErrNotExist error cod.
func (f Files) Get(path string) ([]*drive.File, error) {
	fs, ok := f.files[path]
	if !ok {
		return nil, ErrNotExist
	}
	return fs, nil
}

// File represents the mapping between a full path and a single *drive.File
// stored in Google Drive.
type File struct {
	Path string
	File *drive.File
}

// Helper declarations to be able to sort an array of File values by
// pathname.
type byPath []File

func (a byPath) Len() int           { return len(a) }
func (a byPath) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byPath) Less(i, j int) bool { return a[i].Path < a[j].Path }

// GetSorted returns a array of File values, one for each Google Drive file
// represented by the Files object.  The array is sorted by the files
// pathnames.
func (f Files) GetSorted() []File {
	var files []File
	for path, fileArray := range f.files {
		for _, f := range fileArray {
			files = append(files, File{path, f})
		}
	}
	sort.Sort(byPath(files))
	return files
}

func (f Files) GetSortedUnique() ([]File, []string) {
	allFiles := f.GetSorted()
	var dupes []string
	var files []File
	for i, f := range allFiles {
		// Non-duplicated files are different than their neighbors on both
		// sides (if present).
		if (i == 0 || f.Path != allFiles[i-1].Path) &&
			(i == len(allFiles)-1 || f.Path != allFiles[i+1].Path) {
			files = append(files, f)
		} else if dupes == nil || dupes[len(dupes)-1] != f.Path {
			dupes = append(dupes, f.Path)
		}
	}

	return files, dupes
}

// GetFilesUnderPath returns a Files object that represents all of the
// files stored in GoogleDrive under the given path.  The 'recursive'
// parameter indicates whether the contents of folders under the given path
// should be included and 'includeBase' indicates whether the file
// corresponding to the given path's folder should be included.
func (gd *GDrive) GetFilesUnderPath(path string,
	recursive, includeBase, mustExist bool) (Files, error) {
	files := newFiles()

	// Start by getting the file or files that correspond to the given
	// path.
	pathfiles, err := gd.GetFiles(path)
	if err != nil {
		return files, err
	}
	if len(pathfiles) == 0 && mustExist {
		return files, ErrNotExist
	}

	for _, f := range pathfiles {
		if IsFolder(f) {
			if includeBase {
				files.Add(path, f)
			}
			err := gd.getFolderContentsRecursive(path, f, recursive, &files)
			if err != nil {
				return files, err
			}
		} else {
			files.Add(path, f)
		}
	}
	return files, nil
}

func (gd *GDrive) getFolderContentsRecursive(path string, parentFolder *drive.File,
	recursive bool, files *Files) error {
	query := fmt.Sprintf("trashed=false and '%s' in parents", parentFolder.Id)
	dirfiles, err := gd.runQuery(query)
	if err != nil {
		return err
	}

	for _, f := range dirfiles {
		filepath := filepath.Clean(path + "/" + f.Title)
		files.Add(filepath, f)
		if IsFolder(f) && recursive {
			err := gd.getFolderContentsRecursive(filepath, f, recursive, files)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// IsFolder returns a boolean indicating whether the given *drive.File is a
// folder.
func IsFolder(f *drive.File) bool {
	return f.MimeType == "application/vnd.google-apps.folder"
}

// GetFileContents returns an io.ReadCloser that provides the contents of
// the given *drive.File.
func (gd *GDrive) GetFileContents(f *drive.File) (io.ReadCloser, error) {
	// The file download URL expires some hours after it's retrieved;
	// re-grab the file right before downloading it so that we have a
	// fresh URL.
	f, err := gd.getFileById(f.Id)
	if err != nil {
		return nil, err
	}

	url := f.DownloadUrl
	if url == "" {
		// Google Drive files can't be downloaded directly via DownloadUrl,
		// but can be exported to another format that can be downloaded.
		url = f.ExportLinks[f.MimeType]
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
// the given *drive.File on Google Drive.
func (gd *GDrive) UpdateProperty(f *drive.File, key string, value string) error {
	var prop *drive.Property
	for _, prop = range f.Properties {
		if prop.Key == key {
			if prop.Value == value {
				// Save the network round-trip and return, since the
				// property already has the desired value.
				return nil
			}
			break
		}
	}

	if prop == nil {
		prop = &drive.Property{Key: key, Value: value}
	}

	for try := 0; ; try++ {
		_, err := gd.svc.Properties.Update(f.Id, key, prop).Do()
		if err == nil {
			// success
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return err
		}
	}
}

// UploadFileContents uploads the file contents given by the io.Reader to
// the given *drive.File.  The upload may fail due to various transient
// network errors; as such, the caller should check to see if a non-nil
// returned error code is a RetryHTTPTransmitError.  In this case, it
// should try again, providing a new io.Reader that points to the start of
// the file.  The 'try' parameter should track how many times this function
// has been called to try to upload the given file due to
// RetryHTTPTransmitErrors.
func (gd *GDrive) UploadFileContents(f *drive.File, contentsReader io.Reader,
	length int64, try int) error {
	// Limit upload bandwidth, if requested..
	if gd.uploadBytesPerSecond > 0 {
		// Kick off a background thread to periodically allow uploading
		// a bit more data.  This allowance is consumed by the
		// rateLimitedReader Read() function.
		launchBandwidthTask(gd.uploadBytesPerSecond)

		contentsReader = &rateLimitedReader{R: ioutil.NopCloser(contentsReader)}
	}

	// Get the PUT request for the upload.
	req, err := prepareUploadPUT(f, contentsReader, length)
	if err != nil {
		return err
	}
	if req == nil {
		// Empty file--we're done.
		return nil
	}

	// And send it off...
	resp, err := gd.oAuthTransport.RoundTrip(req)
	if resp != nil {
		defer googleapi.CloseBody(resp)
	}

	switch gd.handleHTTPResponse(resp, err, try) {
	case Success:
		gd.debug("Success for %s: code %d", f.Title, resp.StatusCode)
		return nil
	case Fail:
		if err == nil {
			log.Fatalf("nil err but fail? resp %v", *resp)
		}
		return err
	case Retry:
		// Otherwise tell the caller to please set up the reader, etc.,
		// again and retry...
		if resp != nil {
			b, _ := ioutil.ReadAll(resp.Body)
			return RetryHTTPTransmitError{StatusCode: resp.StatusCode,
				StatusBody: string(b)}
		}
		return RetryHTTPTransmitError{StatusCode: 500, StatusBody: err.Error()}
	default:
		panic("Unhandled HTTPResult value in switch")
	}
}

func prepareUploadPUT(f *drive.File, contentsReader io.Reader,
	length int64) (*http.Request, error) {
	params := make(url.Values)
	params.Set("uploadType", "media")

	urls := fmt.Sprintf("https://www.googleapis.com/upload/drive/v2/files/%s",
		url.QueryEscape(f.Id))
	urls += "?" + params.Encode()

	contentsReader, contentType, err := detectContentType(contentsReader)
	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequest("PUT", urls, contentsReader)
	googleapi.SetOpaque(req.URL)
	req.ContentLength = length
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "skicka/0.1")

	return req, nil
}

func detectContentType(contentsReader io.Reader) (io.Reader, string, error) {
	// Grab the start of the contents so that we can try to identify
	// the content type.
	contentsHeader := make([]byte, 512)
	headerLength, err := contentsReader.Read(contentsHeader)
	if err != nil {
		if err.Error() == "EOF" {
			// Empty file; this is fine, and we're done.
			return nil, "", nil
		}
		return nil, "", err
	}
	contentType := http.DetectContentType(contentsHeader)

	// Reconstruct a new Reader that returns the same byte stream
	// as the original one, effectively pasting the bytes we read for
	// the content-type identification to the start of what remains in
	// the original io.Reader.
	contentsReader = io.MultiReader(bytes.NewReader(contentsHeader[:headerLength]),
		contentsReader)

	return contentsReader, contentType, nil
}

func (gd *GDrive) getResumableUploadURI(f *drive.File, contentType string,
	length int64) (string, error) {
	params := make(url.Values)
	params.Set("uploadType", "resumable")

	urls := fmt.Sprintf("https://www.googleapis.com/upload/drive/v2/files/%s",
		f.Id)
	urls += "?" + params.Encode()

	body, err := googleapi.WithoutDataWrapper.JSONReader(f)
	if err != nil {
		return "", err
	}

	req, _ := http.NewRequest("PUT", urls, body)
	req.Header.Set("X-Upload-Content-Length", fmt.Sprintf("%d", length))
	req.Header.Set("X-Upload-Content-Type", contentType)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "skicka/0.1")
	// We actually don't need any content in the request, since we're
	// PUTing to an existing file.

	for try := 0; ; try++ {
		gd.debug("Trying to get session URI")
		resp, err := gd.oAuthTransport.RoundTrip(req)

		if err == nil && resp != nil && resp.StatusCode == 200 {
			uri := resp.Header["Location"][0]
			gd.debug("Got resumable upload URI %s", uri)
			return uri, nil
		}
		if err != nil {
			gd.debug("getResumableUploadURI: %v", err)
		}
		if resp != nil {
			b, _ := ioutil.ReadAll(resp.Body)
			gd.debug("getResumableUploadURI status %d\n"+
				"Resp: %+v\nBody: %s", resp.StatusCode, *resp, b)
		}
		if try == maxRetries {
			// Give up...
			return "", err
		}

		gd.exponentialBackoff(try, resp, err)
	}
}

// In certain error cases, we need to go back and query Drive as to how
// much of a file has been successfully uploaded (and thence where we
// should start for the next chunk.)  This function generates that query
// and updates the provided *currentOffset parameter with the result.
func (gd *GDrive) getCurrentChunkStart(sessionURI string, contentLength int64,
	currentOffset *int64) (HTTPResponseResult, error) {
	var err error
	for r := 0; r < maxRetries; r++ {
		req, _ := http.NewRequest("PUT", sessionURI, nil)
		req.Header.Set("Content-Range", fmt.Sprintf("bytes */%d", contentLength))
		req.Header.Set("Content-Length", "0")
		req.ContentLength = 0
		req.Header.Set("User-Agent", "skicka/0.1")
		resp, err := gd.oAuthTransport.RoundTrip(req)

		if resp == nil {
			gd.debug("get current chunk start err %v", err)
			gd.exponentialBackoff(r, resp, err)
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			// 200 or 201 here says we're actually all done
			gd.debug("All done: %d from get content-range response",
				resp.StatusCode)
			return Success, nil
		} else if resp.StatusCode == 308 {
			*currentOffset, err = updateStartFromResponse(resp)
			if err != nil {
				return Fail, err
			}
			gd.debug("Updated start to %d after 308 from get "+
				"content-range...", *currentOffset)
			return Retry, nil
		} else if resp.StatusCode == 401 {
			gd.debug("Trying OAuth2 token refresh.")
			for r := 0; r < 6; r++ {
				if err = gd.oAuthTransport.Refresh(); err == nil {
					gd.debug("Token refresh success")
					// Now once again try the PUT...
					break
				} else {
					gd.debug("refresh try %d fail %v", r, err)
					gd.exponentialBackoff(r, nil, err)
				}
			}
		}
	}
	gd.debug("couldn't recover from 503...")
	return Fail, err
}

// The response we get back from uploading a file chunk includes a "Range"
// field, which gives the range (inclusive!) of bytes that actually were
// successfully uploaded; the ending byte offset may be before the end of
// the range we tried to upload, if there was an error partway through.
// This function returns this offset, so that the next chunk upload can
// start at the right place.
func updateStartFromResponse(resp *http.Response) (int64, error) {
	if rangeString, ok := resp.Header["Range"]; ok && len(rangeString) > 0 {
		var rangeStart, rangeEnd int64
		fmt.Sscanf(rangeString[0], "bytes=%d-%d", &rangeStart, &rangeEnd)
		return rangeEnd + 1, nil
	}
	return 0, fmt.Errorf("Malformed HTTP response to get range %v", *resp)
}

// When we upload a file chunk, a variety of responses may come back from
// the server, ranging from permanent errors to transient errors, to
// success codes.  This function processes the http.Response and maps it to
// a HTTPResponseResult code.  It also may update *try, the conut of how
// many times we've tried in a row to upload a chunk, *start, the current
// offset into the file being uploaded, and *sessionURI, the URI to which
// chunks for the file should be uploaded to.
func (gd *GDrive) handleResumableUploadResponse(resp *http.Response, err error,
	f *drive.File, contentType string, contentLength int64, try *int,
	currentOffset *int64, sessionURI *string) (HTTPResponseResult, error) {
	if *try == maxRetries {
		if err != nil {
			return Fail, fmt.Errorf("giving up after %d retries: %v",
				maxRetries, err)
		} else if resp.StatusCode == 403 {
			return Fail, fmt.Errorf("giving up after %d retries: "+
				"rate limit exceeded", maxRetries)
		} else {
			return Fail, fmt.Errorf("giving up after %d retries: %s",
				maxRetries, resp.Status)
		}
	}

	// Serious error (e.g. connection reset) where we didn't even get a
	// HTTP response back from the server.  Try again (a few times).
	if err != nil {
		gd.debug("handleResumableUploadResponse error %v", err)
		gd.exponentialBackoff(*try, resp, err)
		return Retry, nil
	}

	gd.debug("got status %d from chunk for file %s: %v", resp.StatusCode,
		f.Id, resp)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		// Successfully uploaded the entire file.
		return Success, nil

	case resp.StatusCode == 308:
		// This is the expected response when a chunk was uploaded
		// successfully, but there are still more chunks to do
		// before we're done.
		*currentOffset, err = updateStartFromResponse(resp)
		if err != nil {
			return Fail, err
		}
		*try = 0
		gd.debug("Updated currentOffset to %d after 308", *currentOffset)
		return Retry, nil

	case resp.StatusCode == 404:
		// The upload URI has expired; we need to refresh it. (It
		// has a ~24 hour lifetime.)
		*sessionURI, err = gd.getResumableUploadURI(f, contentType,
			contentLength)
		gd.debug("Got %v after updating URI from 404...", err)
		if err != nil {
			return Fail, err
		}

		// Use the new URI to find the offset to start at.
		*try = 0
		return gd.getCurrentChunkStart(*sessionURI, contentLength,
			currentOffset)

	case resp.StatusCode == 401:
		// After an hour, the OAuth2 token expires and needs to
		// be refreshed.
		gd.debug("Trying OAuth2 token refresh.")
		for r := 0; r < maxRetries; r++ {
			if err = gd.oAuthTransport.Refresh(); err == nil {
				// Successful refresh; make sure we have
				// the right offset for the next time
				// around.
				return gd.getCurrentChunkStart(*sessionURI, contentLength,
					currentOffset)
			}
			gd.debug("Token refresh fail %v", err)
			gd.exponentialBackoff(r, nil, err)
		}
		return Fail, err

	case resp.StatusCode >= 500 && resp.StatusCode <= 599:
		gd.debug("5xx response")
		return gd.getCurrentChunkStart(*sessionURI, contentLength, currentOffset)

	default:
		gd.exponentialBackoff(*try, resp, err)
		return Retry, nil
	}
}

// UploadFileContentsResumable uses the resumable upload protocol to upload
// the file contents from the given Reader to the given *drive.File on
// Google Drive.  This approach is more expensive than UploadFileContents()
// for files under a few megabytes, but is helpful for large files in that
// it's more robust to transient errors and can handle OAuth2 token
// refreshes in the middle of an upload, unlike the regular approach.
func (gd *GDrive) UploadFileContentsResumable(driveFile *drive.File,
	contentsReader io.Reader, contentLength int64) error {
	contentsReader, contentType, err := detectContentType(contentsReader)
	if err != nil {
		return err
	}

	sessionURI, err := gd.getResumableUploadURI(driveFile, contentType,
		contentLength)
	if err != nil {
		return err
	}

	// Kick off a background thread to periodically allow uploading
	// a bit more data.  This allowance is consumed by the
	// rateLimitedReader Read() function.
	launchBandwidthTask(gd.uploadBytesPerSecond)

	// TODO: what is a reasonable default here? Must be 256kB minimum.
	chunkSize := 1024 * 1024

	seekableReader := makeSomewhatSeekableReader(contentsReader, 2*chunkSize)

	// Upload the file in chunks of size chunkSize (or smaller, for the
	// very last chunk).
	for currentOffset, try := int64(0), 0; currentOffset < contentLength; try++ {
		end := currentOffset + int64(chunkSize)
		if end > contentLength {
			end = contentLength
		}
		gd.debug("%s: uploading chunk %d - %d...", driveFile.Title,
			currentOffset, end)

		// We should usually already be at the current offset; this
		// seek should be a no-op except in cases where the
		// previous chunk had an error.
		err = seekableReader.SeekTo(currentOffset)
		if err != nil {
			return err
		}

		// Only allow the current range of bytes to be uploaded
		// with this PUT.
		var body io.Reader = &io.LimitedReader{
			R: seekableReader,
			N: end - currentOffset,
		}
		if gd.uploadBytesPerSecond > 0 {
			body = &rateLimitedReader{R: ioutil.NopCloser(body)}
		}

		req, err := http.NewRequest("PUT", sessionURI, body)
		if err != nil {
			return err
		}
		req.ContentLength = int64(end - currentOffset)
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Content-Range",
			fmt.Sprintf("bytes %d-%d/%d", currentOffset, end-1, contentLength))
		req.Header.Set("User-Agent", "skicka/0.1")

		// Actually (try to) upload the chunk.
		resp, err := gd.oAuthTransport.RoundTrip(req)

		status, err := gd.handleResumableUploadResponse(resp, err,
			driveFile, contentType, contentLength, &try, &currentOffset,
			&sessionURI)

		if resp != nil {
			googleapi.CloseBody(resp)
		}
		if status == Fail {
			return err
		} else if status == Success {
			// The entire file has been uploaded successfully.
			return nil
		}

		// Go around again and do the next chunk...
	}

	// This should perhaps be a panic, as if we are able to upload all
	// of the data but then the Drive API doesn't give us a 2xx reply
	// with the last chunk, then something is really broken.
	return fmt.Errorf("uploaded entire file but didn't get 2xx status on last chunk")
}

// UpdateModificationTime updates the modification time of the given Google
// Drive file to the given time.
func (gd *GDrive) UpdateModificationTime(f *drive.File, newTime time.Time) error {
	gd.debug("updating modification time of %s to %v", f.Title, newTime)

	currentTime, err := GetModificationTime(f)
	if err != nil {
		return err
	}
	if currentTime.Equal(newTime) {
		return nil
	}

	for try := 0; ; try++ {
		fp := &drive.File{ModifiedDate: newTime.UTC().Format(timeFormat)}
		_, err := gd.svc.Files.Patch(f.Id, fp).SetModifiedDate(true).Do()
		if err == nil {
			gd.debug("success: updated modification time on %s", f.Title)
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return err
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

// InsertNewFile creates an actual file in Google Drive with the given
// filename.  The new file is in the folder given by represented by the
// 'parent' parameter, is initialized to have the given modification time
// and the provided Google Drive file properties.  The returned *drive.File
// value represents the file in Drive.
func (gd *GDrive) InsertNewFile(filename string, parent *drive.File,
	modTime time.Time, proplist []*drive.Property) (*drive.File, error) {
	pr := &drive.ParentReference{Id: parent.Id}
	f := &drive.File{
		Title:        filepath.Base(filename),
		MimeType:     "application/octet-stream",
		Parents:      []*drive.ParentReference{pr},
		ModifiedDate: modTime.UTC().Format(timeFormat),
		Properties:   proplist,
	}
	return gd.insertFile(f)
}

// InsertNewFolder creates a new folder in Google Drive with given name.
func (gd *GDrive) InsertNewFolder(filename string, parent *drive.File,
	modTime time.Time, proplist []*drive.Property) (*drive.File, error) {
	pr := &drive.ParentReference{Id: parent.Id}
	f := &drive.File{
		Title:        filename,
		MimeType:     "application/vnd.google-apps.folder",
		ModifiedDate: modTime.UTC().Format(timeFormat),
		Parents:      []*drive.ParentReference{pr},
		Properties:   proplist,
	}
	return gd.insertFile(f)
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

// GetModificationTime returns the modification time of the given Google
// Drive file as a time.Time.
func GetModificationTime(f *drive.File) (time.Time, error) {
	if f.ModifiedDate != "" {
		return time.Parse(time.RFC3339Nano, f.ModifiedDate)
	}
	return time.Unix(0, 0), nil
}

// DeleteFile deletes the given file from Google Drive; note that delection
// is permanent and un-reversable!  (Consider TrashFile instead.)
func (gd *GDrive) DeleteFile(f *drive.File) error {
	for try := 0; ; try++ {
		err := gd.svc.Files.Delete(f.Id).Do()
		if err == nil {
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return fmt.Errorf("unable to delete file %s: %v", f.Title, err)
		}
	}
}

// TrashFile moves the given Google Drive file to the trash; it is not
// immediately deleted permanently.
func (gd *GDrive) TrashFile(f *drive.File) error {
	for try := 0; ; try++ {
		_, err := gd.svc.Files.Trash(f.Id).Do()
		if err == nil {
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, try); err != nil {
			return fmt.Errorf("unable to trash file %s: %v", f.Title, err)
		}
	}
}
