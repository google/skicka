package gdrive

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"testing"
)

func getRandomBytes(n int) []byte {
	bytes := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		panic("random bytes")
	}
	return bytes
}

func TestSeekableReader(t *testing.T) {
	bufSize := 65536
	b := getRandomBytes(bufSize)

	for iter := 0; iter <= 1000; iter++ {
		maxSeek := 128 + (mrand.Int() % bufSize / 2)
		sr := makeSomewhatSeekableReader(bytes.NewReader(b), maxSeek)

		for offset := 0; offset < bufSize-100; {
			wanted := mrand.Int() % (bufSize - offset)
			if wanted == 0 {
				continue
			}
			rbuf := make([]byte, wanted)
			n, err := sr.Read(rbuf)

			if n != wanted {
				t.Fatalf("Expected read of %d, got %d", wanted, n)
			}
			if bytes.Compare(rbuf, b[offset:offset+wanted]) != 0 {
				t.Fatalf("Didn't get back expected bytes")
			}

			offset += n

			delta := 0
			switch mrand.Int() % 3 {
			case 0:
				delta = mrand.Int() % maxSeek
			case 1:
				delta = maxSeek
			}
			if delta != 0 || (mrand.Int()%2) != 0 {
				err = sr.SeekTo(int64(offset - delta))
				if err == nil {
					// The SeekTo() may legitimately fail if we issue
					// multiple seeks backwards without consuming enough
					// via reads.
					offset -= delta
				}
			}
		}
	}
}
