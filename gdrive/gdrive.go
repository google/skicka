package gdrive

import (
	"code.google.com/p/goauth2/oauth"
	"fmt"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/googleapi"
	"log"
	mathrand "math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf(format, args...)
	}
}

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

type GDrive struct {
	OAuthTransport *oauth.Transport
	Svc            *drive.Service
	verbose        debugging
	debug          debugging
}

func New(clientid, clientsecret, cacheFile string, verbose, debug bool) (*GDrive, error) {
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
