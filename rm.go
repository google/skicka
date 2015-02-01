//
// rm.go
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
)

type removeDirectoryError struct {
	path        string
	invokingCmd string
}

func (err removeDirectoryError) Error() string {
	msg := ""
	if err.invokingCmd != "" {
		msg += fmt.Sprintf("%s: ", err.invokingCmd)
	}
	return fmt.Sprintf("%s%s: is a directory", msg, err.path)
}

func rm(args []string) {
	recursive, skipTrash := false, false
	var drivePaths []string

	for _, arg := range args {
		switch {
		case arg == "-r":
			recursive = true
		case arg == "-s":
			skipTrash = true
		default:
			drivePaths = append(drivePaths, arg)
		}
	}

	if len(drivePaths) == 0 {
		fmt.Printf("rm: drive path cannot be empty.\n")
		fmt.Printf("Usage: rm [-r, -s] <drive path ...>\n")
		fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
		os.Exit(1)
	}

	for _, path := range drivePaths {
		if err := checkRmPossible(path, recursive); err != nil {
			if _, ok := err.(gdrive.FileNotFoundError); ok {
				// if there's an encrypted version on drive, let the user know and exit
				oldPath := path
				path += encryptionSuffix
				if err := checkRmPossible(path, recursive); err == nil {
					printErrorAndExit(fmt.Errorf("skicka rm: Found no file with path %s, but found encrypted version with path %s.\n"+
						"If you would like to rm the encrypted version, re-run the command adding the %s extension onto the path.",
						oldPath, path, encryptionSuffix))
				}
			}
			printErrorAndExit(err)
		}

		f, err := gd.GetFile(path)
		if err != nil {
			printErrorAndExit(err)
		}

		if skipTrash {
			err = gd.DeleteFile(f)
		} else {
			err = gd.TrashFile(f)
		}
		if err != nil {
			printErrorAndExit(err)
		}
	}
}

func checkRmPossible(path string, recursive bool) error {
	invokingCmd := "skicka rm"

	driveFile, err := gd.GetFile(path)
	if err != nil {
		switch err.(type) {
		case gdrive.FileNotFoundError:
			return gdrive.NewFileNotFoundError(path, invokingCmd)
		default:
			return err
		}
	}

	if !recursive && gdrive.IsFolder(driveFile) {
		return removeDirectoryError{
			path:        path,
			invokingCmd: invokingCmd,
		}
	}

	return nil
}
