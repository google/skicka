//
// upload.go
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

package gdrive

import (
	"bytes"
	"fmt"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/googleapi"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

// UploadFileContents uploads the file contents given by the io.Reader to
// the given File.  The upload may fail due to various transient network
// errors; as such, the caller should check to see if a non-nil returned
// error code is a RetryHTTPTransmitError.  In this case, it should try
// again, providing a new io.Reader that points to the start of the file.
// The 'try' parameter should track how many times this function has been
// called to try to upload the given file due to RetryHTTPTransmitErrors.
func (gd *GDrive) UploadFileContents(f *File, contentsReader io.Reader,
	length int64, try int) error {
	// Limit upload bandwidth, if requested..
	contentsReader = makeLimitedUploadReader(ioutil.NopCloser(contentsReader))

	// Get the PUT request for the upload.
	req, err := prepareUploadPUT(f.Id, contentsReader, length)
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
		gd.debug("Success for %s: code %d", f.Path, resp.StatusCode)
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
			if resp.Body != nil {
				b, _ := ioutil.ReadAll(resp.Body)
				return RetryHTTPTransmitError{StatusCode: resp.StatusCode,
					StatusBody: string(b)}
			} else {
				return RetryHTTPTransmitError{StatusCode: resp.StatusCode}
			}
		}
		return RetryHTTPTransmitError{StatusCode: 500, StatusBody: err.Error()}
	default:
		panic("Unhandled HTTPResult value in switch")
	}
}

func prepareUploadPUT(id string, contentsReader io.Reader,
	length int64) (*http.Request, error) {
	params := make(url.Values)
	params.Set("uploadType", "media")

	urls := fmt.Sprintf("https://www.googleapis.com/upload/drive/v2/files/%s",
		url.QueryEscape(id))
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
func (gd *GDrive) UploadFileContentsResumable(file *File,
	contentsReader io.Reader, contentLength int64) error {
	contentsReader, contentType, err := detectContentType(contentsReader)
	if err != nil {
		return err
	}

	sessionURI, err := gd.getResumableUploadURI(file.driveFile(), contentType,
		contentLength)
	if err != nil {
		return err
	}

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
		gd.debug("%s: uploading chunk %d - %d...", file.Path,
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
		body = makeLimitedUploadReader(ioutil.NopCloser(body))

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
			file.driveFile(), contentType, contentLength, &try, &currentOffset,
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
