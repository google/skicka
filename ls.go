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
	"os"
	"path/filepath"
	"time"
)

func getPermissionsAsString(driveFile *gdrive.File) (string, error) {
	var str string
	if driveFile.IsFolder() {
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
	dirAsFile := false
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
		} else if arg == "-d" {
			dirAsFile = true
		} else if len(arg) > 0 && arg[0] == '-' {
			fmt.Printf("Usage: skicka ls [-d,-l,-ll,-r] [drive_path ...]\n")
			fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
			return 1
		} else {
			argFilenames = append(argFilenames, arg)
		}
	}

	if len(argFilenames) == 0 {
		argFilenames = append(argFilenames, string(os.PathSeparator))
	}

	errs := 0
	for index, drivePath := range argFilenames {
		drivePath = filepath.Clean(drivePath)

		if len(argFilenames) > 1 {
			fmt.Printf("%s:\n", drivePath)
		}

		// Get the files for the current path from Google Drive.
		files := gd.GetFiles(drivePath)
		if len(files) == 0 {
			fmt.Fprintf(os.Stderr, "skicka: %s: file not found\n", drivePath)
			errs++
			continue
		}

		if !files[0].IsFolder() || dirAsFile {
			// If the user specified a full path to a regular file on the
			// command line or gave the -d option, then don't try to list
			// the directory contents.
			for _, f := range files {
				lsFile(f, recursive, long, longlong)
			}
		} else {
			// Otherwise get either the files in the enclosing folder, or
			// all files under the folder, depending on whether the
			// recursive option was specified.
			includeBase := false
			var files []*gdrive.File
			var err error
			if recursive {
				files, err = gd.GetFilesUnderFolder(drivePath, includeBase)
			} else {
				files, err = gd.GetFilesInFolder(drivePath)
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", drivePath, err)
				errs++
				continue
			}

			for _, f := range files {
				lsFile(f, recursive, long, longlong)
			}

			if len(argFilenames) > 1 && index < len(argFilenames)-1 {
				fmt.Printf("\n")
			}
		}
	}
	return errs
}

// Produce listing output to stdout for a single file.
func lsFile(f *gdrive.File, recursive, long, longlong bool) {
	printFilename := f.Path
	if !recursive {
		printFilename = filepath.Base(printFilename)
	}
	if f.IsFolder() {
		printFilename += string(os.PathSeparator)
	}

	if !long && !longlong {
		fmt.Printf("%s\n", printFilename)
		return
	}

	synctime := f.ModTime
	permString, _ := getPermissionsAsString(f)
	if longlong {
		md5 := f.Md5
		if len(md5) != 32 {
			md5 = "--------------------------------"
		}
		fmt.Printf("%s  %s  %s  %s  %s\n", permString,
			fmtbytes(f.FileSize, true), md5, synctime.Format(time.ANSIC),
			printFilename)
		if debug {
			fmt.Printf("\t[ ")
			for _, prop := range f.Properties {
				fmt.Printf("%s: %s, ", prop.Key, prop.Value)
			}
			fmt.Printf("MimeType: %s, ", f.MimeType)
			fmt.Printf("id: %s ]\n", f.Id)
		}
	} else {
		fmt.Printf("%s  %s  %s  %s\n", permString, fmtbytes(f.FileSize, true),
			synctime.Format(time.ANSIC), printFilename)
	}
}
