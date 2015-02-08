//
// cat.go
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
	"io"
	"os"
	"path/filepath"
)

func cat(args []string) int {
	if len(args) == 0 {
		fmt.Printf("Usage: skicka cat drive_path ...\n")
		fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
		return 1
	}

	errs := 0
	for _, fn := range args {
		fn := filepath.Clean(fn)

		file, err := gd.GetFile(fn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", fn, err)
			errs++
			continue
		}
		if gdrive.IsFolder(file) {
			fmt.Fprintf(os.Stderr, "skicka: %s: is a directory\n", fn)
			errs++
			continue
		}

		contentsReader, err := gd.GetFileContents(file)
		if err != nil {
			if contentsReader != nil {
				contentsReader.Close()
			}
			fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", fn, err)
			errs++
			continue
		}

		_, err = io.Copy(os.Stdout, contentsReader)
		contentsReader.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", fn, err)
			errs++
			continue
		}
	}
	return errs
}
