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

// Maximum number of bytes of data that we are currently allowed to upload
// or download given the bandwidth limits set by the user, if any.  These
// values are reduced by the rateLimitedReader.Read() method when data is
// uploaded or downloaded, and are periodically increased by the task
// launched by launchBandwidthTask().
var availableUploadBytes, availableDownloadBytes int
var uploadBandwidthLimited, downloadBandwidthLimited bool
var bandwidthTaskRunning bool

// Mutex to protect available{Upload,Download}Bytes.
var bandwidthMutex sync.Mutex
var bandwidthCond = sync.NewCond(&bandwidthMutex)

func launchBandwidthTask(uploadBytesPerSecond, downloadBytesPerSecond int) {
	if bandwidthTaskRunning {
		panic("Rate-limited bandwidth management task already launched")
	}

	uploadBandwidthLimited = uploadBytesPerSecond != 0
	downloadBandwidthLimited = downloadBytesPerSecond != 0

	bandwidthMutex.Lock()
	defer bandwidthMutex.Unlock()
	bandwidthTaskRunning = true

	go func() {
		for {
			bandwidthMutex.Lock()

			// Release 1/8th of the per-second limit every 8th of a second.
			// The 92/100 factor in the amount released adds some slop to
			// account for TCP/IP overhead and HTTP headers in an effort to
			// have the actual bandwidth used not exceed the desired limit.
			availableUploadBytes += uploadBytesPerSecond * 92 / 100 / 8
			if availableUploadBytes > uploadBytesPerSecond {
				// Don't ever queue up more than one second's worth of
				// transmission.
				availableUploadBytes = uploadBytesPerSecond
			}
			availableDownloadBytes += downloadBytesPerSecond * 92 / 100 / 8
			if availableDownloadBytes > downloadBytesPerSecond {
				availableDownloadBytes = downloadBytesPerSecond
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

// rateLimitedReader is an io.ReadCloser implementation that returns no
// more bytes than the current value of *availableBytes.  Thus, as long as
// the upload and download paths wrap the underlying io.Readers for local
// files and GETs from Drive (respectively), then we should stay under the
// bandwidth per second limit.
type rateLimitedReader struct {
	R              io.ReadCloser
	availableBytes *int
}

func makeLimitedUploadReader(r io.ReadCloser) io.ReadCloser {
	if uploadBandwidthLimited {
		return rateLimitedReader{R: r, availableBytes: &availableUploadBytes}
	}
	return r
}

func makeLimitedDownloadReader(r io.ReadCloser) io.ReadCloser {
	if downloadBandwidthLimited {
		return rateLimitedReader{R: r, availableBytes: &availableDownloadBytes}
	}
	return r
}

func (lr rateLimitedReader) Read(dst []byte) (int, error) {
	// Loop until some amount of bandwidth is available.
	bandwidthMutex.Lock()
	for {
		if *lr.availableBytes < 0 {
			panic("bandwidth budget went negative")
		}
		if *lr.availableBytes > 0 {
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
	if n > *lr.availableBytes {
		n = *lr.availableBytes
	}

	// Update the budget for the maximum amount of what we may consume and
	// relinquish the lock so that other workers can claim bandwidth.
	*lr.availableBytes -= n
	bandwidthMutex.Unlock()

	read, err := lr.R.Read(dst[:n])
	if read < n {
		// It may turn out that the amount we read from the original
		// io.Reader is less than the caller asked for; in this case,
		// we give back the bandwidth that we reserved but didn't use.
		bandwidthMutex.Lock()
		*lr.availableBytes += n - read
		bandwidthMutex.Unlock()
	}

	return read, err
}

func (lr rateLimitedReader) Close() error {
	return lr.R.Close()
}

///////////////////////////////////////////////////////////////////////////

// somewhatSeekableReader is an io.Reader that can seek backwards from the
// current offset up to len(buf) bytes. It's useful for chunked file
// uploads, where we may need to rewind a bit after a failed chunk, but
// definitely don't want to pay the overhead of having the entire file in
// memory to be able to rewind arbitrarily for.
//
// It is implemented as a ring-buffer: the current offset in buf to read
// from is in readOffset, and the current offset to copy values read from
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
	// If the caller has called SeekTo() to move backwards from the
	// current read point of the underlying reader R, we start by
	// copying values from our local buffer into the output buffer.
	nCopy := int(ssr.writeOffset - ssr.readOffset)
	if nCopy > 0 {
		// Don't plan to copy more than the buffer can hold
		if nCopy > len(b) {
			nCopy = len(b)
		}

		start := int(ssr.readOffset % int64(len(ssr.buf)))
		end := int((ssr.readOffset + int64(nCopy)) % int64(len(ssr.buf)))

		// First, copy up to the end of the ring buffer (if needed).
		n := copy(b[:nCopy], ssr.buf[start:])
		if n < nCopy {
			// If that wasn't enough, go and copy bytes from the start of
			// the ring buffer.
			n2 := copy(b[n:], ssr.buf[:end])
			if n+n2 != nCopy {
				panic("somewhatSeekableReader: logic error")
			}
		}

		// Advance the b[] slice and the read offset to account for what
		// we've copied.
		b = b[nCopy:]
		ssr.readOffset += int64(nCopy)
	}

	// Once we're through the values we have buffered from previous reads,
	// we read from the underlying reader. Note that we read into b[]
	// starting at the point where we stopped copying buffered values.
	nRead, err := ssr.R.Read(b)

	if nRead > 0 {
		// Update the local buffer of read values.
		if ssr.readOffset != ssr.writeOffset {
			panic("somewhatSeekableReader: unexped offsets")
		}
		// First, advance the offsets to represent how far we are into the
		// Reader.
		ssr.readOffset += int64(nRead)
		ssr.writeOffset += int64(nRead)

		nSave := nRead
		if nSave > len(ssr.buf) {
			// Don't try to save more bytes than we have storage for in the
			// buffer.
			nSave = len(ssr.buf)
			b = b[nRead-nSave:]
		}

		// Start and end offsets for where we'll be writing into the
		// ring-buffer.
		start := (ssr.writeOffset - int64(nSave)) % int64(len(ssr.buf))
		end := ssr.writeOffset % int64(len(ssr.buf))

		// First, copy from b up to the end of the buffer.
		n := copy(ssr.buf[start:], b)
		if n < nSave {
			// If that wasn't enough, copy from the start of the buffer to
			// the end offset.
			n2 := copy(ssr.buf[:end], b[n:])
			if n+n2 != nSave {
				panic("somewhatSeekableReader: logic error")
			}
		}
	}

	return nCopy + nRead, err
}

func (ssr *somewhatSeekableReader) SeekTo(offset int64) error {
	switch {
	case offset < 0:
		return fmt.Errorf("invalid seek to negative offset %d", offset)
	case offset > ssr.writeOffset:
		// We could support seeking past the extent that the file has been
		// read (by just doing a bunch of Read() calls), but this isn't
		// really necessary currently...
		return fmt.Errorf("invalid seek to %d, past current write offset %d",
			offset, ssr.writeOffset)
	case ssr.writeOffset-offset > int64(len(ssr.buf)):
		return fmt.Errorf("can't seek back to %d; current offset %d",
			offset, ssr.writeOffset)
	default:
		ssr.readOffset = offset
		return nil
	}
}
