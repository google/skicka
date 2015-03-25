//
// readers.go
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
	"io"
	"sync"
	"time"
)

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
	}

	bandwidthTaskRunning = true
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
