package main

import (
	"bytes"
	"github.com/cheggaaa/pb"
	"os"
	"testing"
)

type DevNullWriter struct {
}

func (w *DevNullWriter) Write(p []byte) (n int, err error) {
	file, err := os.Create(os.DevNull)
	defer file.Close()
	return file.Write(p)
}

func TestThatProgressBarsExpectedTotalCanChange(t *testing.T) {
	nBytesToDownload := int64(1 << 8)
	progressBar := pb.New64(nBytesToDownload).SetUnits(pb.U_BYTES)
	progressBar.Output = new(DevNullWriter)
	progressBar.Start()
	progressBar.Add64(int64(1 << 7))

	if 1<<8 != progressBar.Total {
		t.Fatalf("Expected the progress bar's total to be %bb but was %bb",
			1<<8, progressBar.Total)
	}

	progressBar.Total = int64(1 << 9)

	if 1<<8 != progressBar.Total-progressBar.Add64(1<<7) {
		t.Fatalf("Expected the progress bar's current progress to be 0b%b but was 0b%b",
			1<<8, progressBar.Add(0))
	}

	progressBar.Finish()
}

func TestThatProgressBarCanRewindProgress(t *testing.T) {
	nBytesToDownload := int64(1 << 8)
	progressBar := pb.New64(nBytesToDownload).SetUnits(pb.U_BYTES)
	progressBar.Output = new(DevNullWriter)
	progressBar.Start()

	reader := bytes.NewReader(make([]byte, nBytesToDownload))
	dst := make([]byte, 1<<7)
	byteCountingReader := &ByteCountingReader{
		R: reader,
	}

	read, _ := byteCountingReader.Read(dst)
	if 1<<7 != read {
		t.Fatalf("Expected to read %d bytes but read %d byte[s]", 1<<7, read)
	}

	// Pretend a failure happened, rewind progress
	progressBar.Add64(int64(0 - byteCountingReader.bytesRead))
	// reset variables
	reader = bytes.NewReader(make([]byte, nBytesToDownload))
	byteCountingReader = &ByteCountingReader{
		R: reader,
	}

	read, _ = byteCountingReader.Read(dst)
	read, _ = byteCountingReader.Read(dst)
	if len(dst) != read || nBytesToDownload != int64(byteCountingReader.bytesRead) {
		t.Fatalf("Expected to read %d bytes but read %d byte[s] and "+
			"to accumulate %d bytes but accumulated %d byte[s]", len(dst), nBytesToDownload)
	}
}
