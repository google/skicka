//
// du.go
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
	"os"
	"path/filepath"
	"sort"
)

func du(args []string) int {
	if len(args) == 0 {
		args = append(args, string(os.PathSeparator))
	}

	errs := 0
	for _, drivePath := range args {
		drivePath = filepath.Clean(drivePath)

		// Get all of the files under drivePath from Google Drive.
		includeBase := false
		files, err := gd.GetFilesUnderFolder(drivePath, includeBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", drivePath, err)
			errs++
			continue
		}

		// folderSize keeps track of the size in bytes of each folder in
		// the hierarchy.
		folderSize := make(map[string]int64)
		// dirNames tracks all of the names of directories seen so far.
		var dirNames []string
		totalSize := int64(0)

		for _, f := range files {
			if f.IsFolder() {
				dirNames = append(dirNames, f.Path)
			} else {
				// Accumulate the file's contribution to the directory it's
				// in as well as all of the directories above it.
				sz := f.FileSize
				totalSize += sz
				dirName := filepath.Clean(filepath.Dir(f.Path))
				for ; dirName != string(os.PathSeparator) && dirName != "."; dirName = filepath.Dir(dirName) {
					folderSize[dirName] += sz
				}
				folderSize[string(os.PathSeparator)] += sz
			}
		}

		// Print output.
		sort.Strings(dirNames)
		for _, d := range dirNames {
			fmt.Printf("%s  %s\n", fmtbytes(folderSize[d], true), d)
		}
		fmt.Printf("%s  %s\n", fmtbytes(totalSize, true), drivePath)
	}
	return errs
}
