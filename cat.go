package main

import (
	"fmt"
	"github.com/google/skicka/gdrive"
	"io"
	"os"
	"path/filepath"
)

func Cat(args []string) {
	if len(args) != 1 {
		printUsageAndExit()
	}
	filename := filepath.Clean(args[0])

	file, err := gd.GetFile(filename)
	timeDelta("Get file descriptors from Google Drive")
	if err != nil {
		printErrorAndExit(err)
	}
	if gdrive.IsFolder(file) {
		printErrorAndExit(fmt.Errorf("skicka: %s: is a directory", filename))
	}

	contentsReader, err := gd.GetFileContents(file)
	if contentsReader != nil {
		defer contentsReader.Close()
	}
	if err != nil {
		printErrorAndExit(fmt.Errorf("skicka: %s: %v", filename, err))
	}

	_, err = io.Copy(os.Stdout, contentsReader)
	if err != nil {
		printErrorAndExit(fmt.Errorf("skicka: %s: %v", filename, err))
	}
}
