package gdrive

import (
	"bytes"
	"code.google.com/p/goauth2/oauth"
	"fmt"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/googleapi"
	"io"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const ResumableUploadMinSize = 64 * 1024 * 1024

///////////////////////////////////////////////////////////////////////////

type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf(format, args...)
	}
}

///////////////////////////////////////////////////////////////////////////

type FileNotFoundError struct {
	path        string
	invokingCmd string
}

func NewFileNotFoundError(path, cmd string) FileNotFoundError {
	return FileNotFoundError{path: path, invokingCmd: cmd}
}

func (err FileNotFoundError) Error() string {
	msg := ""
	if err.invokingCmd != "" {
		msg += fmt.Sprintf("%s: ", err.invokingCmd)
	}
	return fmt.Sprintf("%s%s: No such file or directory", msg, err.path)
}

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
// This value is reduced by the RateLimitedReader.Read() method when data is
// uploaded or downloaded, and is periodically increased by the task
// launched by launchBandwidthTask().
var bandwidthBudget int
var bandwidthTaskRunning bool

// Mutex to protect bandwidthBudget.
var bandwidthBudgetMutex sync.Mutex

func launchBandwidthTask(bytesPerSecond int) {
	if bytesPerSecond == 0 {
		// No limit, so no need to launch the task.
		return
	}

	bandwidthBudgetMutex.Lock()
	if bandwidthTaskRunning {
		bandwidthBudgetMutex.Unlock()
		return
	}

	bandwidthTaskRunning = true
	bandwidthBudgetMutex.Unlock()

	go func() {
		for {
			bandwidthBudgetMutex.Lock()

			// Release 1/8th of the per-second limit every 8th of a second.
			// The 92/100 factor in the amount released adds some slop to
			// account for TCP/IP overhead in an effort to have the actual
			// bandwidth used not exceed the desired limit.
			bandwidthBudget += bytesPerSecond * 92 / 100 / 8
			if bandwidthBudget > bytesPerSecond {
				bandwidthBudget = bytesPerSecond
			}

			bandwidthBudgetMutex.Unlock()
			time.Sleep(time.Duration(125) * time.Millisecond)
		}
	}()
}

// RateLimitedReader is an io.Reader implementation that returns no more bytes
// than the current value of bandwidthBudget.  Thus, as long as the upload and
// download paths wrap the underlying io.Readers for local files and GETs
// from Drive (respectively), then we should stay under the bandwidth per
// second limit.
type RateLimitedReader struct {
	R io.Reader
}

func (lr RateLimitedReader) Read(dst []byte) (int, error) {
	// Loop until some amount of bandwidth is available.
	for {
		bandwidthBudgetMutex.Lock()
		if bandwidthBudget < 0 {
			panic("bandwidth budget went negative")
		}
		if bandwidthBudget > 0 {
			break
		}

		// No further uploading is possible at the moment;
		// sleep for a bit and then we'll try the loop
		// again and see if we have better luck...
		// TODO: we could also wait on a condition
		// variable and wait to be signaled by the "add
		// more available upload bytes" thread.
		bandwidthBudgetMutex.Unlock()
		time.Sleep(time.Duration(100) * time.Millisecond)
	}

	// The caller would like us to return up to this many bytes...
	n := len(dst)

	// but don't try to upload more than we're allowed to...
	if n > bandwidthBudget {
		n = bandwidthBudget
	}

	// Update the budget for the maximum amount of what we may consume and
	// relinquish the lock so that other workers can claim bandwidth.
	bandwidthBudget -= n
	bandwidthBudgetMutex.Unlock()

	read, err := lr.R.Read(dst[:n])
	if read < n {
		// It may turn out that the amount we read from the original
		// io.Reader is less than the caller asked for; in this case,
		// we give back the bandwidth that we reserved but didn't use.
		bandwidthBudgetMutex.Lock()
		bandwidthBudget += n - read
		bandwidthBudgetMutex.Unlock()
	}

	return read, err
}

///////////////////////////////////////////////////////////////////////////

// SomewhatSeekableReader is an io.Reader that can seek backwards from the
// current offset up to 'bufSize' bytes. It's useful for chunked file
// uploads, where we may need to rewind a bit after a failed chunk, but
// definitely don't want to pay the overhead of having the entire file in
// memory.
//
// It is implemented as a ring-buffer: the current offset in buf to read
// from is in readOffset, and the currentOffset to copy values read from
// the reader to is in writeOffset.  Both of these are taken mod bufSize
// when used to compute offsets into buf.
type SomewhatSeekableReader struct {
	R                       io.Reader
	buf                     []byte
	bufSize                 int
	readOffset, writeOffset int64
}

func MakeSomewhatSeekableReader(r io.Reader, size int) *SomewhatSeekableReader {
	return &SomewhatSeekableReader{
		R:           r,
		buf:         make([]byte, size),
		bufSize:     size,
		readOffset:  0,
		writeOffset: 0,
	}
}

func (ssr *SomewhatSeekableReader) Read(b []byte) (int, error) {
	// If the caller has called Seek() to move backwards from the
	// current read point of the underlying reader R, we start by
	// copying values from our local buffer into the output buffer.
	nCopied := 0
	if ssr.readOffset < ssr.writeOffset {
		for ; ssr.readOffset < ssr.writeOffset && nCopied < len(b); nCopied++ {
			b[nCopied] = ssr.buf[ssr.readOffset%int64(ssr.bufSize)]
			ssr.readOffset++
		}
		if nCopied == len(b) {
			return nCopied, nil
		}
	}

	// Once we're through the values we have locally buffered, we read
	// from the underlying reader. Note that we read into b[] starting
	// at the point where we stopped copying local values.
	nRead, err := ssr.R.Read(b[nCopied:])

	// Now update our local buffer of read values.  Note that this loop
	// is a bit wasteful in the case where nRead > ssr.bufSize; some of
	// the values it writes will be clobbered by a later iteration of
	// the loop.  (It's not clear that this is a big enough issue to
	// really worry about.)
	for i := 0; i < nRead; i++ {
		ssr.buf[ssr.writeOffset%int64(ssr.bufSize)] = b[nCopied+i]
		ssr.readOffset++
		ssr.writeOffset++
	}

	return nCopied + nRead, err
}

func (ssr *SomewhatSeekableReader) SeekTo(offset int64) error {
	if offset > ssr.writeOffset {
		panic("invalid seek")
	}
	if ssr.writeOffset-offset > int64(ssr.bufSize) {
		return fmt.Errorf("can't seek back to %d; current offset %d",
			offset, ssr.writeOffset)
	}
	ssr.readOffset = offset
	return nil
}

///////////////////////////////////////////////////////////////////////////

type GDrive struct {
	OAuthTransport            *oauth.Transport
	Svc                       *drive.Service
	verbose                   debugging
	debug                     debugging
	upload_bytes_per_second   int
	download_bytes_per_second int
}

func New(clientid, clientsecret, cacheFile string,
	upload_bytes_per_second, download_bytes_per_second int,
	verbose, debug bool) (*GDrive, error) {
	config := &oauth.Config{
		ClientId:     clientid,
		ClientSecret: clientsecret,
		Scope:        "https://www.googleapis.com/auth/drive",
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://accounts.google.com/o/oauth2/token",
		TokenCache:   oauth.CacheFile(cacheFile),
	}

	gd := GDrive{OAuthTransport: &oauth.Transport{
		Config:    config,
		Transport: http.DefaultTransport,
	},
		verbose: debugging(verbose),
		debug:   debugging(debug),
		upload_bytes_per_second:   upload_bytes_per_second,
		download_bytes_per_second: download_bytes_per_second,
	}

	token, err := config.TokenCache.Token()
	if err != nil {
		authURL := config.AuthCodeURL("state")
		fmt.Printf("Go to the following link in your browser:\n%v\n", authURL)
		fmt.Printf("Enter verification code: ")
		var code string
		fmt.Scanln(&code)
		token, err = gd.OAuthTransport.Exchange(code)
		if err != nil {
			return nil, err
		}
	}
	gd.OAuthTransport.Token = token

	gd.Svc, err = drive.New(gd.OAuthTransport.Client())
	return &gd, err
}

func (gd *GDrive) AddProperty(key, value string, driveFile *drive.File) error {
	prop := &drive.Property{Key: key, Value: value}

	for ntries := 0; ; ntries++ {
		_, err := gd.Svc.Properties.Insert(driveFile.Id, prop).Do()
		if err == nil {
			return nil
		} else if err = gd.tryToHandleDriveAPIError(err, ntries); err != nil {
			return fmt.Errorf("unable to create %s property: %v",
				prop.Key, err)
		}
	}
}

// There are a number of cases where the Google Drive API returns an error
// code but where it's possible to recover from the error; examples include
// 401 errors when the OAuth2 token expires after an hour, or 403/500 errors
// when we make too many API calls too quickly and we get a rate limit error.
// This function takes an error returned by a Drive API call and the number
// of times that we've tried to call the API entrypoint already and does
// its best to handle the error.
//
// If it thinks it may have been successful, it returns nil, and the caller
// should try the call again. For unrecoverable errors (or too many errors
// in a row), it returns the error code back and the caller should stop trying.
func (gd *GDrive) tryToHandleDriveAPIError(err error, ntries int) error {
	gd.debug.Printf("tryToHandleDriveAPIError: ntries %d error %T %+v",
		ntries, err, err)

	maxAPIRetries := 6
	if ntries == maxAPIRetries {
		return err
	}
	switch err := err.(type) {
	case *googleapi.Error:
		if err.Code == 401 {
			// After an hour, the OAuth2 token expires and needs to
			// be refreshed.
			gd.debug.Printf("Trying OAuth2 token refresh.")
			if err := gd.OAuthTransport.Refresh(); err == nil {
				// Success
				return nil
			}
			// Otherwise fall through to sleep/backoff...
		}
	}

	gd.exponentialBackoff(ntries, nil, err)
	return nil
}

func (gd *GDrive) exponentialBackoff(ntries int, resp *http.Response, err error) {
	s := time.Duration(1<<uint(ntries))*time.Second +
		time.Duration(mathrand.Int()%1000)*time.Millisecond
	time.Sleep(s)
	if resp != nil {
		gd.debug.Printf("exponential backoff: slept for resp %d...", resp.StatusCode)
	} else {
		gd.debug.Printf("exponential backoff: slept for error %v...", err)
	}
}

// TODO: make private
// Google Drive identifies each file with a unique Id string; this function
// returns the *drive.File corresponding to a given Id, dealing with
// timeouts and transient errors.
func (gd *GDrive) GetFileById(id string) (*drive.File, error) {
	for ntries := 0; ; ntries++ {
		file, err := gd.Svc.Files.Get(id).Do()
		if err == nil {
			return file, nil
		} else if err = gd.tryToHandleDriveAPIError(err, ntries); err != nil {
			return nil, err
		}
	}
}

// Google Drive files can have properties associated with them, which are
// basically maps from strings to strings. Given a Google Drive file and a
// property name, this function returns the property value, if the named
// property is present.
func GetProperty(driveFile *drive.File, name string) (string, error) {
	for _, prop := range driveFile.Properties {
		if prop.Key == name {
			return prop.Value, nil
		}
	}
	return "", fmt.Errorf("%s: property not found", name)
}

// Returns the *drive.File corresponding to a given path starting from the
// root of the Google Drive filesystem.  (Note that *drive.File is used to
// represent both files and folders in Google Drive.)
func (gd *GDrive) GetFile(path string) (*drive.File, error) {
	parent, err := gd.GetFileById("root")
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

		query := fmt.Sprintf("title='%s' and '%s' in parents and trashed=false",
			dir, parent.Id)
		files := gd.RunQuery(query)

		if len(files) == 0 {
			return nil, FileNotFoundError{
				path: path,
			}
		} else if len(files) > 1 {
			return nil, fmt.Errorf("%s: multiple files found", path)
		} else {
			parent = files[0]
		}
	}
	return parent, nil
}

// TODO: make private
// Execute the given query with the Google Drive API, returning an array of
// files that match the query's conditions. Handles transient HTTP errors and
// the like.
func (gd *GDrive) RunQuery(query string) []*drive.File {
	pageToken := ""
	var result []*drive.File
	for {
		q := gd.Svc.Files.List().Q(query)
		if pageToken != "" {
			q = q.PageToken(pageToken)
		}

		for ntries := 0; ; ntries++ {
			r, err := q.Do()
			if err == nil {
				result = append(result, r.Items...)
				pageToken = r.NextPageToken
				break
			} else if err = gd.tryToHandleDriveAPIError(err, ntries); err != nil {
				log.Fatalf("couldn't run Google Drive query: %v",
					err)
			}
		}

		if pageToken == "" {
			break
		}
	}
	return result
}

// Add all of the the *drive.Files in 'parentFolder' to the provided map from
// pathnames to *driveFiles. Assumes that 'path' is the path down to
// 'parentFolder' when constructing pathnames of files. If 'recursive' is true,
// also includes all files in the full hierarchy under the given folder.
// Otherwise, only the files directly in the folder are returned.
func (gd *GDrive) getFolderContents(path string, parentFolder *drive.File,
	recursive bool, existingFiles map[string]*drive.File) error {
	query := fmt.Sprintf("trashed=false and '%s' in parents", parentFolder.Id)
	dirfiles := gd.RunQuery(query)
	for _, f := range dirfiles {
		filepath := filepath.Clean(path + "/" + f.Title)
		if _, ok := existingFiles[filepath]; ok == true {
			// This shouldn't happen in principle, but Drive does
			// allow multiple files to have the same title. It's not
			// obvious how to reconcile this with Unix file
			// semantics, so we just disallow it entirely.
			return fmt.Errorf("%s: duplicate file found on Google Drive",
				filepath)
		}
		existingFiles[filepath] = f
		if IsFolder(f) && recursive {
			err := gd.getFolderContents(filepath, f, recursive, existingFiles)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Returns a map from strings to *drive.Files that represents all existing
// files in Google Drive at the folder identified by 'path'. If 'recursive' is
// true, directories under the given path are processed recursively.
// 'includeBase' indicates whether the *drive.File for the given path should
// be included in the result, and 'mustExist' indicates whether an error
// should be returned if the given path doesn't exist on Drive.
func (gd *GDrive) GetFilesAtRemotePath(path string, recursive, includeBase,
	mustExist bool) (map[string]*drive.File, error) {
	existingFiles := make(map[string]*drive.File)
	file, err := gd.GetFile(path)
	if err != nil {
		if !mustExist {
			return existingFiles, nil
		}
		return existingFiles, err
	}

	if IsFolder(file) {
		err := gd.getFolderContents(path, file, recursive, existingFiles)
		if err != nil {
			return existingFiles, err
		}
		if includeBase {
			existingFiles[path] = file
		}
	} else {
		existingFiles[path] = file
	}
	return existingFiles, nil
}

func IsFolder(f *drive.File) bool {
	return f.MimeType == "application/vnd.google-apps.folder"
}

// Get the contents of the *drive.File as an io.ReadCloser.
func (gd *GDrive) GetFileContentsReader(driveFile *drive.File) (io.ReadCloser, error) {
	// The file download URL expires some hours after it's retrieved;
	// re-grab the file right before downloading it so that we have a
	// fresh URL.
	driveFile, err := gd.GetFileById(driveFile.Id)
	if err != nil {
		return nil, err
	}

	url := driveFile.DownloadUrl
	if url == "" {
		url = driveFile.ExportLinks[driveFile.MimeType]
	}

	for ntries := 0; ; ntries++ {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := gd.OAuthTransport.RoundTrip(request)

		switch gd.handleHTTPResponse(resp, err, ntries) {
		case Success:
			return resp.Body, nil
		case Fail:
			return nil, err
		case Retry:
		}
	}
}

type HTTPResponseResult int

const (
	Success    HTTPResponseResult = iota
	Retry                         = iota
	Fail                          = iota
	RefreshURI                    = iota
)

const maxHTTPRetries = 6

// We've gotten an *http.Response (maybe) and an error (maybe) back after
// performing some HTTP operation; this function takes care of figuring
// out if the operation succeeded, refreshes OAuth2 tokens if expiration
// was the cause of the failure, takes care of exponential back-off for
// transient errors, etc.  It then returns a HTTPResponseResult to the
// caller, indicating how it should proceed.
func (gd *GDrive) handleHTTPResponse(resp *http.Response, err error, ntries int) HTTPResponseResult {
	if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return Success
	}

	if ntries == maxHTTPRetries {
		return Fail
	}

	if resp != nil && resp.StatusCode == 401 {
		// After an hour, the OAuth2 token expires and needs to
		// be refreshed.
		gd.debug.Printf("Trying OAuth2 token refresh.")
		if err = gd.OAuthTransport.Refresh(); err == nil {
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
	gd.exponentialBackoff(ntries, resp, err)
	return Retry
}

func (gd *GDrive) UpdateProperty(driveFile *drive.File, name string, newValue string) error {
	if oldValue, err := GetProperty(driveFile, name); err == nil {
		if oldValue == newValue {
			return nil
		}
	}

	for nTriesGet := 0; ; nTriesGet++ {
		prop, err := gd.Svc.Properties.Get(driveFile.Id, name).Do()
		if err == nil {
			prop.Value = newValue
			for nTriesUpdate := 0; ; nTriesUpdate++ {
				_, err = gd.Svc.Properties.Update(driveFile.Id,
					name, prop).Do()
				if err == nil {
					// success
					return nil
				} else if err = gd.tryToHandleDriveAPIError(err, nTriesUpdate); err != nil {
					return err
				}
			}
		} else if err = gd.tryToHandleDriveAPIError(err, nTriesGet); err != nil {
			return err
		}
	}
}

// Upload the file contents given by the io.Reader to the given *drive.File.
func (gd *GDrive) UploadFileContents(driveFile *drive.File, contentsReader io.Reader,
	length int64, currentTry int) error {
	// Kick off a background thread to periodically allow uploading
	// a bit more data.  This allowance is consumed by the
	// RateLimitedReader Read() function.
	launchBandwidthTask(gd.upload_bytes_per_second)

	// Only run the resumable upload path for large files (it
	// introduces some overhead that isn't worth it for smaller files.)
	if length > ResumableUploadMinSize {
		return gd.uploadFileContentsResumable(driveFile, contentsReader, length)
	}

	// Limit upload bandwidth, if requested..
	if gd.upload_bytes_per_second > 0 {
		contentsReader = &RateLimitedReader{R: contentsReader}
	}

	// Get the PUT request for the upload.
	req, err := prepareUploadPUT(driveFile, contentsReader, length)
	if err != nil {
		return err
	}
	if req == nil {
		// Empty file--we're done.
		return nil
	}

	// And send it off...
	resp, err := gd.OAuthTransport.RoundTrip(req)
	if resp != nil {
		defer googleapi.CloseBody(resp)
	}

	switch gd.handleHTTPResponse(resp, err, currentTry) {
	case Success:
		gd.debug.Printf("Success for %s: code %d", driveFile.Title, resp.StatusCode)
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

func prepareUploadPUT(driveFile *drive.File, contentsReader io.Reader,
	length int64) (*http.Request, error) {
	params := make(url.Values)
	params.Set("uploadType", "media")

	urls := fmt.Sprintf("https://www.googleapis.com/upload/drive/v2/files/%s",
		url.QueryEscape(driveFile.Id))
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

func (gd *GDrive) getResumableUploadURI(driveFile *drive.File, contentType string,
	length int64) (string, error) {
	params := make(url.Values)
	params.Set("uploadType", "resumable")

	urls := fmt.Sprintf("https://www.googleapis.com/upload/drive/v2/files/%s",
		driveFile.Id)
	urls += "?" + params.Encode()

	body, err := googleapi.WithoutDataWrapper.JSONReader(driveFile)
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

	for ntries := 0; ; ntries++ {
		gd.debug.Printf("Trying to get session URI")
		resp, err := gd.OAuthTransport.RoundTrip(req)

		if err == nil && resp != nil && resp.StatusCode == 200 {
			uri := resp.Header["Location"][0]
			gd.debug.Printf("Got resumable upload URI %s", uri)
			return uri, nil
		}
		if err != nil {
			gd.debug.Printf("getResumableUploadURI: %v", err)
		}
		if resp != nil {
			b, _ := ioutil.ReadAll(resp.Body)
			gd.debug.Printf("getResumableUploadURI status %d\n"+
				"Resp: %+v\nBody: %s", resp.StatusCode, *resp, b)
		}
		if ntries == 5 {
			// Give up...
			return "", err
		}

		gd.exponentialBackoff(ntries, resp, err)
	}
}

// In certain error cases, we need to go back and query Drive as to how
// much of a file has been successfully uploaded (and thence where we
// should start for the next chunk.)  This function generates that query
// and updates the provided *currentOffset parameter with the result.
func (gd *GDrive) getCurrentChunkStart(sessionURI string, contentLength int64,
	currentOffset *int64) (HTTPResponseResult, error) {
	var err error
	for r := 0; r < 6; r++ {
		req, _ := http.NewRequest("PUT", sessionURI, nil)
		req.Header.Set("Content-Range", fmt.Sprintf("bytes */%d", contentLength))
		req.Header.Set("Content-Length", "0")
		req.ContentLength = 0
		req.Header.Set("User-Agent", "skicka/0.1")
		resp, err := gd.OAuthTransport.RoundTrip(req)

		if resp == nil {
			gd.debug.Printf("get current chunk start err %v", err)
			gd.exponentialBackoff(r, resp, err)
			continue
		}

		defer resp.Body.Close()
		b, _ := ioutil.ReadAll(resp.Body)
		gd.debug.Printf("Get current chunk start err %v resp status %d, "+
			"body %s\nRESP %v",
			err, resp.StatusCode, b, *resp)

		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			// 200 or 201 here says we're actually all done
			gd.debug.Printf("All done: %d from get content-range response",
				resp.StatusCode)
			return Success, nil
		} else if resp.StatusCode == 308 {
			*currentOffset, err = updateStartFromResponse(resp)
			if err != nil {
				return Fail, err
			}
			gd.debug.Printf("Updated start to %d after 308 from get "+
				"content-range...", *currentOffset)
			return Retry, nil
		} else if resp.StatusCode == 401 {
			gd.debug.Printf("Trying OAuth2 token refresh.")
			for r := 0; r < 6; r++ {
				if err = gd.OAuthTransport.Refresh(); err == nil {
					gd.debug.Printf("Token refresh success")
					// Now once again try the PUT...
					break
				} else {
					gd.debug.Printf("refresh try %d fail %v", r, err)
					gd.exponentialBackoff(r, nil, err)
				}
			}
		}
	}
	gd.debug.Printf("couldn't recover from 503...")
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
// a HTTPResponseResult code.  It also may update *ntries, the conut of how
// many times we've tried in a row to upload a chunk, *start, the current
// offset into the file being uploaded, and *sessionURI, the URI to which
// chunks for the file should be uploaded to.
func (gd *GDrive) handleResumableUploadResponse(resp *http.Response, err error, driveFile *drive.File,
	contentType string, contentLength int64, ntries *int, currentOffset *int64,
	sessionURI *string) (HTTPResponseResult, error) {
	if *ntries == 6 {
		if err != nil {
			return Fail, fmt.Errorf("giving up after 6 retries: %v", err)
		} else if resp.StatusCode == 403 {
			return Fail, fmt.Errorf("giving up after 6 retries: " +
				"rate limit exceeded")
		} else {
			return Fail, fmt.Errorf("giving up after 6 retries: %s",
				resp.Status)
		}
	}

	// Serious error (e.g. connection reset) where we didn't even get a
	// HTTP response back from the server.  Try again (a few times).
	if err != nil {
		gd.debug.Printf("handleResumableUploadResponse error %v", err)
		gd.exponentialBackoff(*ntries, resp, err)
		return Retry, nil
	}

	gd.debug.Printf("got status %d from chunk for file %s", resp.StatusCode,
		driveFile.Id, resp)

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
		*ntries = 0
		gd.debug.Printf("Updated currentOffset to %d after 308", *currentOffset)
		return Retry, nil

	case resp.StatusCode == 404:
		// The upload URI has expired; we need to refresh it. (It
		// has a ~24 hour lifetime.)
		*sessionURI, err = gd.getResumableUploadURI(driveFile,
			contentType, contentLength)
		gd.debug.Printf("Got %v after updating URI from 404...", err)
		if err != nil {
			return Fail, err
		}

		// Use the new URI to find the offset to start at.
		*ntries = 0
		return gd.getCurrentChunkStart(*sessionURI, contentLength,
			currentOffset)

	case resp.StatusCode == 401:
		// After an hour, the OAuth2 token expires and needs to
		// be refreshed.
		gd.debug.Printf("Trying OAuth2 token refresh.")
		for r := 0; r < 6; r++ {
			if err = gd.OAuthTransport.Refresh(); err == nil {
				// Successful refresh; make sure we have
				// the right offset for the next time
				// around.
				return gd.getCurrentChunkStart(*sessionURI, contentLength,
					currentOffset)
			}
			gd.debug.Printf("Token refresh fail %v", err)
			gd.exponentialBackoff(r, nil, err)
		}
		return Fail, err

	case resp.StatusCode >= 500 && resp.StatusCode <= 599:
		gd.debug.Printf("5xx response")
		return gd.getCurrentChunkStart(*sessionURI, contentLength, currentOffset)

	default:
		gd.exponentialBackoff(*ntries, resp, err)
		return Retry, nil
	}
}

func (gd *GDrive) uploadFileContentsResumable(driveFile *drive.File, contentsReader io.Reader,
	contentLength int64) error {
	contentsReader, contentType, err := detectContentType(contentsReader)
	if err != nil {
		return err
	}

	sessionURI, err := gd.getResumableUploadURI(driveFile, contentType,
		contentLength)
	if err != nil {
		return err
	}

	// TODO: what is a reasonable default here? Must be 256kB minimum.
	chunkSize := 1024 * 1024

	seekableReader := MakeSomewhatSeekableReader(contentsReader, 2*chunkSize)

	// Upload the file in chunks of size chunkSize (or smaller, for the
	// very last chunk).
	for currentOffset, ntries := int64(0), 0; currentOffset < contentLength; ntries++ {
		end := currentOffset + int64(chunkSize)
		if end > contentLength {
			end = contentLength
		}
		gd.debug.Printf("%s: uploading chunk %d - %d...", driveFile.Title,
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
		if gd.upload_bytes_per_second > 0 {
			body = &RateLimitedReader{R: body}
		}

		all, err := ioutil.ReadAll(body)
		if int64(len(all)) != end-currentOffset {
			log.Fatalf("reader gave us %d bytes, expected %d, bye", len(all),
				end-currentOffset)
		}
		req, _ := http.NewRequest("PUT", sessionURI, bytes.NewReader(all))

		//		req, _ := http.NewRequest("PUT", sessionURI, body)
		req.ContentLength = int64(end - currentOffset)
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Content-Range",
			fmt.Sprintf("bytes %d-%d/%d", currentOffset, end-1, contentLength))
		req.Header.Set("User-Agent", "skicka/0.1")

		// Actually (try to) upload the chunk.
		resp, err := gd.OAuthTransport.RoundTrip(req)

		status, err := gd.handleResumableUploadResponse(resp, err,
			driveFile, contentType, contentLength, &ntries, &currentOffset,
			&sessionURI)

		if resp != nil {
			googleapi.CloseBody(resp)
		}
		if status == Fail {
			return err
		}

		if status == Success {
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
