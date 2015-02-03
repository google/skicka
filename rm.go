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

func rm(args []string) int {
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
		return 1
	}

	errs := 0
	for _, path := range drivePaths {
		if err := checkRmPossible(path, recursive); err != nil {
			if err == gdrive.ErrNotExist {
				// if there's an encrypted version on drive, let the user know and exit
				encpath := path + encryptionSuffix
				if err := checkRmPossible(encpath, recursive); err == nil {
					fmt.Fprintf(os.Stderr, "skicka: %s: file not found, but found "+
						"encrypted version with path %s.\n"+
						"To remove the encrypted version, re-run the command adding "+
						"the %s extension.\n",
						path, encpath, encryptionSuffix)
					errs++
					continue
				}
			}
			fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", path, err)
			errs++
			continue
		}

		f, err := gd.GetFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", path, err)
			errs++
			continue
		}

		if skipTrash {
			err = gd.DeleteFile(f)
		} else {
			err = gd.TrashFile(f)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", path, err)
			errs++
			continue
		}
	}
	return errs
}

func checkRmPossible(path string, recursive bool) error {
	driveFile, err := gd.GetFile(path)
	if err != nil {
		return err
	} else if !recursive && gdrive.IsFolder(driveFile) {
		return fmt.Errorf("skicka: %s: is a folder", path)
	}
	return nil
}
