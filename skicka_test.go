package main

import (
	"bytes"
	"fmt"
	"github.com/cheggaaa/pb"
	"google.golang.org/api/drive/v2"
	"os"
	runtimeDebug "runtime/debug"
	"strings"
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

type notExistsQueryer int

func (q notExistsQueryer) getDriveFile(path string) (*drive.File, error) {
	return nil, fileNotFoundError{
		path: path,
	}
}

func (q notExistsQueryer) isFolder(file *drive.File) bool {
	return false
}

type existsQueryer int

func (q existsQueryer) getDriveFile(path string) (*drive.File, error) {
	return &drive.File{
		MimeType: path,
	}, nil
}

func (q existsQueryer) isFolder(file *drive.File) bool {
	return strings.HasSuffix(file.MimeType, "dir")
}

func TestRmArgumentErrorHandling(t *testing.T) {
	recursive, skipTrash := false, false
	driveFile := "/fake/drive/file"
	driveDir := "/fake/drive/dir"

	var notExister notExistsQueryer = 2
	var exister existsQueryer = 2
	noSuchFileErrorMessage := fmt.Sprintf("rm: %s: No such file or directory", driveFile)
	noSuchDirErrorMessage := fmt.Sprintf("rm: %s: No such file or directory", driveDir)
	isADirectoryErrorMessage := fmt.Sprintf("rm: %s: is a directory", driveDir)

	//There are 16 possible (valid) variations of the parameters, these are:
	//R: recursive, S: skip trash, E: existence of file, [F/D]: file or directory
	//		| !R | !S | !E |  F |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	expectErrorWithMessage(t,
		checkRmArguments(driveFile, recursive, skipTrash, notExister),
		noSuchFileErrorMessage)

	//		| !R | !S | !E |  D |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	expectErrorWithMessage(t,
		checkRmArguments(driveDir, recursive, skipTrash, notExister),
		noSuchDirErrorMessage)

	//		| !R | !S |  E |  F |
	//		Should succeed
	if err := checkRmArguments(driveFile, recursive, skipTrash, exister); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}

	//		| !R | !S |  E |  D |
	//		Should fail with error message; rm: <drive path>: is a directory
	expectErrorWithMessage(t,
		checkRmArguments(driveDir, recursive, skipTrash, exister),
		isADirectoryErrorMessage)

	//		| !R |  S | !E |  F |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	skipTrash = true
	expectErrorWithMessage(t,
		checkRmArguments(driveFile, recursive, skipTrash, notExister),
		noSuchFileErrorMessage)

	//		| !R |  S | !E |  D |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	expectErrorWithMessage(t,
		checkRmArguments(driveDir, recursive, skipTrash, notExister),
		noSuchDirErrorMessage)

	//		| !R |  S |  E |  F |
	//		Should succeed
	if err := checkRmArguments(driveFile, recursive, skipTrash, exister); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}

	//		| !R |  S |  E |  D |
	//		Should fail with error message; rm: <drive path>: is a directory
	expectErrorWithMessage(t,
		checkRmArguments(driveDir, recursive, skipTrash, exister),
		isADirectoryErrorMessage)

	//		|  R | !S | !E |  F |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	recursive = true
	skipTrash = false
	expectErrorWithMessage(t,
		checkRmArguments(driveFile, recursive, skipTrash, notExister),
		noSuchFileErrorMessage)

	//		|  R | !S | !E |  D |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	expectErrorWithMessage(t,
		checkRmArguments(driveDir, recursive, skipTrash, notExister),
		noSuchDirErrorMessage)

	//		|  R | !S |  E |  F |
	//		Should succeed
	if err := checkRmArguments(driveFile, recursive, skipTrash, exister); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}

	//		|  R | !S |  E |  D |
	//		Should succeed
	if err := checkRmArguments(driveDir, recursive, skipTrash, exister); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}

	skipTrash = true
	//		|  R |  S | !E |  F |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	expectErrorWithMessage(t,
		checkRmArguments(driveFile, recursive, skipTrash, notExister),
		noSuchFileErrorMessage)

	//		|  R |  S | !E |  D |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	expectErrorWithMessage(t,
		checkRmArguments(driveDir, recursive, skipTrash, notExister),
		noSuchDirErrorMessage)

	//		|  R |  S |  E |  F |
	//		Should succeed
	if err := checkRmArguments(driveFile, recursive, skipTrash, exister); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}

	//		|  R |  S |  E |  D |
	//		Should succeed
	if err := checkRmArguments(driveDir, recursive, skipTrash, exister); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}
}

func TestEmptyDrivePathArgument(t *testing.T) {
	var exister existsQueryer = 2
	err := checkRmArguments("", true, true, exister)
	if _, ok := err.(CommandSyntaxError); !ok {
		t.Fatalf("checkRmArguments should return a CommandSyntaxError when path is empty "+
			"but returned: %v", err)
	}
	expectErrorWithMessage(t, err, rmSyntaxError.Error())
}

func expectErrorWithMessage(t *testing.T, err error, msg string) {
	if err == nil || err.Error() != msg {
		runtimeDebug.PrintStack()
		t.Fatalf("An error should have been returned with the message %s, but %v was returned",
			msg, err)
	}
}
