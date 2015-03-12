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
	bcr := &byteCountingReader{
		R: reader,
	}

	read, _ := bcr.Read(dst)
	if 1<<7 != read {
		t.Fatalf("Expected to read %d bytes but read %d byte[s]", 1<<7, read)
	}

	// Pretend a failure happened, rewind progress
	progressBar.Add64(int64(0 - bcr.bytesRead))
	// reset variables
	reader = bytes.NewReader(make([]byte, nBytesToDownload))
	bcr = &byteCountingReader{
		R: reader,
	}

	read, _ = bcr.Read(dst)
	read, _ = bcr.Read(dst)
	if len(dst) != read || nBytesToDownload != int64(bcr.bytesRead) {
		t.Fatalf("Expected to read %d bytes but read %d byte[s] and "+
			"to accumulate %d bytes but accumulated %d byte[s]", len(dst), read,
			nBytesToDownload, bcr.bytesRead)
	}
}

/*
type notExistsQueryer struct {
	path      string
	recursive bool
}

func (q notExistsQueryer) getDriveFile() (*drive.File, error) {
	return nil, fileNotFoundError{
		path: q.path,
	}
}

func (q notExistsQueryer) drivePath() string {
	return q.path
}

type existsQueryer notExistsQueryer

func (q existsQueryer) getDriveFile() (*drive.File, error) {
	var mimeType string
	if strings.HasSuffix(q.path, "dir") {
		mimeType = "application/vnd.google-apps.folder"
	}
	return &drive.File{
		MimeType: mimeType,
	}, nil
}

func (q existsQueryer) drivePath() string {
	return q.path
}

func TestRmArgumentErrorHandling(t *testing.T) {
	recursive := false
	driveFile := "/fake/drive/file"
	driveDir := "/fake/drive/dir"
	noSuchFileErrorMessage := fmt.Sprintf("skicka rm: %s: No such file or directory", driveFile)
	noSuchDirErrorMessage := fmt.Sprintf("skicka rm: %s: No such file or directory", driveDir)
	isADirectoryErrorMessage := fmt.Sprintf("skicka rm: %s: is a directory", driveDir)

	var notExister notExistsQueryer = notExistsQueryer{
		recursive: recursive,
	}

	var exister existsQueryer = existsQueryer{
		recursive: recursive,
	}

	//There are 8 possible (valid) variations of the parameters, these are:
	//R: recursive, E: existence of file, [F/D]: file or directory
	//		| !R | !E |  F |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	notExister.path = driveFile
	expectErrorWithMessage(t,
		checkRmPossible(notExister, recursive),
		noSuchFileErrorMessage)

	//		| !R | !E |  D |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	notExister.path = driveDir
	expectErrorWithMessage(t,
		checkRmPossible(notExister, recursive),
		noSuchDirErrorMessage)

	//		| !R |  E |  F |
	//		Should succeed
	exister.path = driveFile
	if err := checkRmPossible(exister, recursive); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}

	//		| !R |  E |  D |
	//		Should fail with error message; rm: <drive path>: is a directory
	exister.path = driveDir
	expectErrorWithMessage(t,
		checkRmPossible(exister, recursive),
		isADirectoryErrorMessage)

	//		|  R | !E |  F |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	recursive = true
	notExister.path = driveFile
	expectErrorWithMessage(t,
		checkRmPossible(notExister, recursive),
		noSuchFileErrorMessage)

	//		|  R | !E |  D |
	//		Should fail with error message: rm: <drive path>: no such file or directory
	notExister.path = driveDir
	expectErrorWithMessage(t,
		checkRmPossible(notExister, recursive),
		noSuchDirErrorMessage)

	//		|  R |  E |  F |
	//		Should succeed
	exister.path = driveFile
	if err := checkRmPossible(exister, recursive); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}

	//		|  R |  E |  D |
	//		Should succeed
	exister.path = driveDir
	if err := checkRmPossible(exister, recursive); err != nil {
		t.Fatalf("An error occurred when it shouldn't have: %v", err)
	}
}

func TestEmptyDrivePathArgument(t *testing.T) {
	var exister existsQueryer = existsQueryer{
		path:      "",
		recursive: false,
	}

	err := checkRmPossible(exister, false)
	if _, ok := err.(CommandSyntaxError); !ok {
		t.Fatalf("checkRmPossible should return a CommandSyntaxError when path is empty "+
			"but returned: %v", err)
	}
	expectErrorWithMessage(t, err, rmSyntaxError.Error())
}

type deleter struct {
	deleteCalled, trashCalled, skipTrash bool
}

func (d *deleter) deleteDriveFile() error {
	d.deleteCalled = true
	return nil
}

func (d *deleter) trashDriveFile() (*drive.File, error) {
	d.trashCalled = true
	return nil, nil
}

func (d *deleter) isSkipTrash() bool {
	return d.skipTrash
}

func TestDeleteFuncDiffentiatesBetweenDeleteAndTrash(t *testing.T) {
	d := new(deleter)
	d.skipTrash = true
	deleteDriveFile(d)

	if d.deleteCalled != true {
		t.Fatal("When skipTrash is true, then driveDeleter's delete function should " +
			"be called, but it wasn't")
	}

	d = new(deleter)
	deleteDriveFile(d)

	if d.trashCalled != true {
		t.Fatal("When skipTrash is false, then driveDeleter's trash function should " +
			"be called, but it wasn't")
	}
}

func expectErrorWithMessage(t *testing.T, err error, msg string) {
	if err == nil || err.Error() != msg {
		runtimeDebug.PrintStack()
		t.Fatalf("An error should have been returned with the message %s, but this was returned: %v",
			msg, err)
	}
}
*/
