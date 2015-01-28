package gdrive

import (
	"code.google.com/p/goauth2/oauth"
	"fmt"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/googleapi"
	"log"
	mathrand "math/rand"
	"net/http"
	"time"
)

type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf(format, args...)
	}
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
