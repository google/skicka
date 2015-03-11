package main

import (
	"bytes"
	"io"
	"testing"
)

func TestInitializationOfByteCountingReader(t *testing.T) {
	byteReader := bytes.NewReader(make([]byte, 6))
	bcr := byteCountingReader{
		R: byteReader,
	}

	if bcr.bytesRead != 0 {
		t.Fatalf("Expected an initialization value of 0 of the byteCountReader, but got: %v",
			bcr.bytesRead)
	}

	if bcr.R != byteReader {
		t.Fatal("Initialization of ByteCountingReader struct failure")
	}
}

func TestMultipleReadsAccumlateBytesCorrectly(t *testing.T) {
	// Create a reader, wrap it with a ByteCountingReader,
	// read some stuff, and verify that the number of bytes
	// read the number of bytes that should have been read.
	sixBytes := []byte{'a', 'b', 'c', 'd', 'e', 'f'}
	byteReader := bytes.NewReader(sixBytes)
	oneByte := make([]byte, 1)
	bcr := byteCountingReader{
		R: byteReader,
	}

	for read, err := bcr.Read(oneByte); read > 0; {
		if err != nil {
			t.Fatalf("Expected no error, but got: %v", err)
		}
		if read != 1 {
			t.Fatalf("Expected to read 1 byte, but instead read %d byte[s].", read)
		}
		read, err = bcr.Read(oneByte)
	}

	expectedByteCount := int64(6)
	if bcr.bytesRead != expectedByteCount {
		t.Fatalf("The byte counting reader should have accumulated %d bytes, but accumulated %d",
			expectedByteCount, bcr.bytesRead)
	}
}

func TestSingleReadAccumulatesBytesCorrectly(t *testing.T) {
	sixBytes := []byte{'a', 'b', 'c', 'd', 'e', 'f'}
	byteReader := bytes.NewReader(sixBytes)
	tenBytes := make([]byte, 10)
	bcr := byteCountingReader{
		R: byteReader,
	}
	read, err := bcr.Read(tenBytes)
	if err != nil && io.EOF != err {
		t.Fatalf("Expected that if error is not nil, then it is of type io.EOF.  Here it was of type %T", err)
	}

	if read != 6 {
		t.Fatalf("Expected to have read 6 bytes, but read %d byte[s]", read)
	}

	if bcr.bytesRead != 6 {
		t.Fatalf("Expected to have accumulated 6 bytes, but accumulated %d byte[s]",
			bcr.bytesRead)
	}
}

func TestByteCountingReaderCanAccumulateFromDifferentReaders(t *testing.T) {
	sixBytes, eightBytes := make([]byte, 6), make([]byte, 8)
	sixByteReader, eightByteReader := bytes.NewReader(sixBytes), bytes.NewReader(eightBytes)
	buffer := make([]byte, 3)

	bcr := byteCountingReader{
		R: sixByteReader,
	}

	read := 1
	for read > 0 {
		read, _ = bcr.Read(buffer)
	}

	bcr.R = eightByteReader
	read = 1
	for read > 0 {
		read, _ = bcr.Read(buffer)
	}

	expectedAccumulatedBytes := int64(14)
	if expectedAccumulatedBytes != bcr.bytesRead {
		t.Fatalf("Expected ByteCountingReader to have read %d byte[s], but read %d byte[s]",
			expectedAccumulatedBytes, bcr.bytesRead)
	}
}

func TestByteCountingReaderImplementsIoReader(t *testing.T) {
	byteReader := bytes.NewReader(make([]byte, 6))
	bcr := &byteCountingReader{
		R: byteReader,
	}

	_, ok := interface{}(bcr).(io.Reader)
	if !ok {
		t.Fatal("Expected ByteCountingReader to implement io.Reader interface, but it did not.")
	}
}
