//
// mkdir.go
// Copyright(c)2014-2015 Google, Inc.
//
// This file is part of skicka.
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
	"github.com/google/skicka/gdrive"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func mkdirUsage() {
	fmt.Printf("Usage: skicka mkdir [-p] <drive path...>\n")
	fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
	os.Exit(1)
}

func mkdir(args []string) int {
	if len(args) == 0 {
		mkdirUsage()
	}

	i := 0
	makeIntermediate := false
	if args[0] == "-p" {
		makeIntermediate = true
		i++
	} else if args[0][0] == '-' {
		mkdirUsage()
	}

	root, err := gd.GetFile(gdrive.GetPathChar())
	if err != nil {
		printErrorAndExit(fmt.Errorf("unable to get Drive root directory: %v", err))
	}

	errs := 0
	for ; i < len(args); i++ {
		drivePath := filepath.Clean(args[i])

		parent := root
		dirs := strings.Split(drivePath, gdrive.GetPathChar())
		nDirs := len(dirs)
		pathSoFar := ""
		// Walk through the directories in the path in turn.
		for index, dir := range dirs {
			if dir == "" {
				// The first string in the split is "" if the
				// path starts with a '/'.
				continue
			}
			pathSoFar += gdrive.GetPathChar() + dir

			// Get the Drive File file for our current point in the path.
			file, err := gd.GetFileInFolder(dir, parent)
			if err != nil {
				if err == gdrive.ErrNotExist {
					// File not found; create the folder if we're at the last
					// directory in the provided path or if -p was specified.
					// Otherwise, error time.
					if index+1 == nDirs || makeIntermediate {
						parent, err = createDriveFolder(dir, 0755, time.Now(), parent)
						debug.Printf("Creating folder %s", pathSoFar)
						if err != nil {
							fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", pathSoFar, err)
							errs++
							break
						}
					} else {
						fmt.Fprintf(os.Stderr, "skicka: %s: no such directory\n",
							pathSoFar)
						errs++
						break
					}
				} else {
					fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", pathSoFar, err)
					errs++
					break
				}
			} else {
				// Found it; if it's a folder this is good, unless it's
				// the folder we were supposed to be creating.
				if index+1 == nDirs && !makeIntermediate {
					fmt.Fprintf(os.Stderr, "skicka: %s: already exists\n", pathSoFar)
					errs++
					break
				} else if !gdrive.IsFolder(file) {
					fmt.Fprintf(os.Stderr, "skicka: %s: not a folder\n", pathSoFar)
					errs++
					break
				} else {
					parent = file
				}
			}
		}
	}
	return errs
}
