//
// http.go
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
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

type HTTPResponseResult int

const (
	Success    HTTPResponseResult = iota
	Retry                         = iota
	Fail                          = iota
	RefreshURI                    = iota
)

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

	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
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

func (gd *GDrive) exponentialBackoff(try int, resp *http.Response, err error) {
	s := time.Duration(1<<uint(try))*time.Second +
		time.Duration(rand.Int()%1000)*time.Millisecond
	time.Sleep(s)
	if resp != nil {
		gd.debug("exponential backoff: slept %v for resp %d...", s,
			resp.StatusCode)
	} else {
		gd.debug("exponential backoff: slept %v for error %v...", s, err)
	}
}
