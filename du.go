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
	"github.com/google/skicka/gdrive"
	"path/filepath"
	"sort"
)

func du(args []string) {
	if len(args) == 0 {
		printUsageAndExit()
	}

	for _, drivePath := range args {
		drivePath = filepath.Clean(drivePath)

		recursive := true
		includeBase := false
		mustExist := true
		existingFiles, err := gd.GetFilesUnderFolder(drivePath, recursive, includeBase,
			mustExist)
		if err != nil {
			printErrorAndExit(fmt.Errorf("skicka: %v", err))
		}

		// Accumulate the size in bytes of each folder in the hierarchy
		folderSize := make(map[string]int64)
		var dirNames []string
		totalSize := int64(0)
		for name, f := range existingFiles {
			if gdrive.IsFolder(f) {
				dirNames = append(dirNames, name)
			} else {
				totalSize += f.FileSize
				dirName := filepath.Clean(filepath.Dir(name))
				for ; dirName != "/" && dirName != "."; dirName = filepath.Dir(dirName) {
					folderSize[dirName] += f.FileSize
				}
				folderSize["/"] += f.FileSize
			}
		}

		// Print output
		sort.Strings(dirNames)
		for _, d := range dirNames {
			fmt.Printf("%s  %s\n", fmtbytes(folderSize[d], true), d)
		}
		fmt.Printf("%s  %s\n", fmtbytes(totalSize, true), drivePath)
	}
}
