//
// ls.go
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
	"google.golang.org/api/drive/v2"
	"os"
	"path/filepath"
	"time"
)

func getPermissionsAsString(driveFile *drive.File) (string, error) {
	var str string
	if gdrive.IsFolder(driveFile) {
		str = "d"
	} else {
		str = "-"
	}

	perm, err := getPermissions(driveFile)
	if err != nil {
		// No permissions are available if the file was uploaded via the
		// Drive Web page, for example.
		str += "?????????"
	} else {
		rwx := "rwx"
		for i := 0; i < 9; i++ {
			if perm&(1<<(8-uint(i))) != 0 {
				str += string(rwx[i%3])
			} else {
				str += "-"
			}
		}
	}
	return str, nil
}

func ls(args []string) int {
	// Parse command line arguments.
	long := false
	longlong := false
	recursive := false
	var argFilenames []string
	for _, arg := range args {
		if len(argFilenames) > 0 {
			// After the end of command-line arguments, all subsequent args
			// are treated as filenames, regardless of whether they match
			// any of the flags.
			argFilenames = append(argFilenames, arg)
		} else if arg == "-l" {
			long = true
		} else if arg == "-ll" {
			longlong = true
		} else if arg == "-r" {
			recursive = true
		} else if arg[0] == '-' {
			fmt.Printf("Usage: skicka ls [-l,-ll,-r] [drive_path ...]\n")
			fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
			return 1
		} else {
			argFilenames = append(argFilenames, arg)
		}
	}

	if len(argFilenames) == 0 {
		argFilenames = append(argFilenames, pathSeparator())
	}

	errs := 0
	for index, drivePath := range argFilenames {
		drivePath = filepath.Clean(drivePath)

		if len(argFilenames) > 1 {
			fmt.Printf("%s:\n", drivePath)
		}

		// Get the files for the current path from Google Drive.
		includeBase := false
		mustExist := true
		files, err := gd.GetFilesUnderPath(drivePath, recursive, includeBase,
			mustExist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", drivePath, err)
			errs++
			continue
		}

		// Sort the individual filenames returned.
		sorted := files.GetSorted()

		for _, f := range sorted {
			printFilename := f.Path
			if !recursive {
				printFilename = filepath.Base(printFilename)
			}
			if gdrive.IsFolder(f.File) {
				printFilename += pathSeparator()
			}
			if long || longlong {
				synctime, _ := gdrive.GetModificationTime(f.File)
				permString, _ := getPermissionsAsString(f.File)
				if longlong {
					md5 := f.File.Md5Checksum
					if len(md5) != 32 {
						md5 = "--------------------------------"
					}
					fmt.Printf("%s  %s  %s  %s  %s\n", permString,
						fmtbytes(f.File.FileSize, true), md5,
						synctime.Format(time.ANSIC), printFilename)
					if debug {
						fmt.Printf("\t[ ")
						for _, prop := range f.File.Properties {
							fmt.Printf("%s: %s, ", prop.Key,
								prop.Value)
						}
						fmt.Printf("id: %s ]\n", f.File.Id)
					}
				} else {
					fmt.Printf("%s  %s  %s  %s\n", permString,
						fmtbytes(f.File.FileSize, true),
						synctime.Format(time.ANSIC), printFilename)
				}
			} else {
				fmt.Printf("%s\n", printFilename)
			}
		}

		if len(argFilenames) > 1 && index < len(argFilenames)-1 {
			fmt.Printf("\n")
		}
	}
	return errs
}
