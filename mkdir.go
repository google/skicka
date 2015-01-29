package main

import (
	"fmt"
	"github.com/google/skicka/gdrive"
	"path/filepath"
	"strings"
	"time"
)

func Mkdir(args []string) {
	makeIntermediate := false

	i := 0
	for ; i+1 < len(args); i++ {
		if args[i] == "-p" {
			makeIntermediate = true
		} else {
			printUsageAndExit()
		}
	}
	drivePath := filepath.Clean(args[i])

	parent, err := gd.GetFile("/")
	if err != nil {
		printErrorAndExit(fmt.Errorf("unable to get Drive root directory: %v", err))
	}

	dirs := strings.Split(drivePath, "/")
	nDirs := len(dirs)
	pathSoFar := ""
	// Walk through the directories in the path in turn.
	for index, dir := range dirs {
		if dir == "" {
			// The first string in the split is "" if the
			// path starts with a '/'.
			continue
		}
		pathSoFar += "/" + dir

		// Get the Drive File file for our current point in the path.
		file, err := gd.GetFileInFolder(dir, parent)
		if err != nil {
			if _, ok := err.(gdrive.FileNotFoundError); ok {
				// File not found; create the folder if we're at the last
				// directory in the provided path or if -p was specified.
				// Otherwise, error time.
				if index+1 == nDirs || makeIntermediate {
					parent, err = createDriveFolder(dir, 0755, time.Now(), parent)
					debug.Printf("Creating folder %s", pathSoFar)
					if err != nil {
						printErrorAndExit(fmt.Errorf("skicka: %s: %v",
							pathSoFar, err))
					}
				} else {
					printErrorAndExit(fmt.Errorf("skicka: %s: no such "+
						"directory", pathSoFar))
				}
			} else {
				printErrorAndExit(err)
			}
		} else {
			// Found it; if it's a folder this is good, unless it's
			// the folder we were supposed to be creating.
			if index+1 == nDirs && !makeIntermediate {
				printErrorAndExit(fmt.Errorf("skicka: %s: already exists",
					pathSoFar))
			} else if !gdrive.IsFolder(file) {
				printErrorAndExit(fmt.Errorf("skicka: %s: not a folder",
					pathSoFar))
			} else {
				parent = file
			}
		}
	}
}
