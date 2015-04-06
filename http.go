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

package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"time"
)

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
	log.Printf("http request: %s--->response: %+v\n--->err: %v", dump, resp, err)
	return resp, err
}

type flakyTransport struct {
	transport http.RoundTripper
	rng       *rand.Rand
	endTime   time.Time
}

func newFlakyTransport(transport http.RoundTripper) http.RoundTripper {
	seed := time.Now().UTC().UnixNano()
	log.Printf("Flaky rand seed %d", seed)
	return flakyTransport{transport: transport, rng: rand.New(rand.NewSource(seed))}
}

func (ft flakyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if time.Now().After(ft.endTime) {
		if ft.rng.Float32() > .01 {
			return ft.transport.RoundTrip(req)
		}
		delta := time.Duration(ft.rng.Int31()%(10*1000)) * time.Millisecond
		ft.endTime = time.Now().Add(delta)
		log.Printf("Flaky http until %s", ft.endTime.String())
	}

	codes := []int{401, 403, 404, 408, 500, 503}
	c := codes[int(ft.rng.Int31())%len(codes)]
	return &http.Response{Status: fmt.Sprintf("%d ERROR", c), StatusCode: c},
		fmt.Errorf("OH NO")
}
