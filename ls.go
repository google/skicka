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
	"path/filepath"
	"sort"
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

func ls(args []string) {
	// Parse command line arguments.
	long := false
	longlong := false
	recursive := false
	var argFilenames []string
	for _, value := range args {
		switch {
		case value == "-l":
			long = true
		case value == "-ll":
			longlong = true
		case value == "-r":
			recursive = true
		default:
			argFilenames = append(argFilenames, value)
		}
	}

	if len(argFilenames) == 0 {
		argFilenames = append(argFilenames, "/")
	}

	for index, drivePath := range argFilenames {
		drivePath = filepath.Clean(drivePath)

		if len(argFilenames) > 1 {
			fmt.Printf("%s:\n", drivePath)
		}

		// Get the files for the current path from Google Drive.
		includeBase := false
		mustExist := true
		existingFiles, err := gd.GetFilesUnderFolder(drivePath, recursive, includeBase,
			mustExist)
		if err != nil {
			printErrorAndExit(fmt.Errorf("skicka: %v", err))
		}

		// Sort the individual filenames returned.
		var filenames []string
		for f := range existingFiles {
			filenames = append(filenames, f)
		}
		sort.Strings(filenames)

		for _, f := range filenames {
			file := existingFiles[f]
			printFilename := f
			if !recursive {
				printFilename = filepath.Base(f)
			}
			if gdrive.IsFolder(file) {
				printFilename += "/"
			}
			if long || longlong {
				synctime, _ := gdrive.GetModificationTime(file)
				permString, _ := getPermissionsAsString(file)
				if longlong {
					md5 := file.Md5Checksum
					if len(md5) != 32 {
						md5 = "--------------------------------"
					}
					fmt.Printf("%s  %s  %s  %s  %s\n", permString,
						fmtbytes(file.FileSize, true), md5,
						synctime.Format(time.ANSIC), printFilename)
					if debug {
						fmt.Printf("\t[ ")
						for _, prop := range file.Properties {
							fmt.Printf("%s: %s, ", prop.Key,
								prop.Value)
						}
						fmt.Printf("id: %s ]\n", file.Id)
					}
				} else {
					fmt.Printf("%s  %s  %s  %s\n", permString,
						fmtbytes(file.FileSize, true),
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
}
