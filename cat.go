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

func Cat(args []string) {
	if len(args) == 0 {
		printUsageAndExit()
	}

	for _, fn := range args {
		fn := filepath.Clean(fn)

		file, err := gd.GetFile(fn)
		if err != nil {
			printErrorAndExit(err)
		}
		if gdrive.IsFolder(file) {
			printErrorAndExit(fmt.Errorf("skicka: %s: is a directory", fn))
		}

		contentsReader, err := gd.GetFileContents(file)
		if err != nil {
			if contentsReader != nil {
				contentsReader.Close()
			}
			printErrorAndExit(fmt.Errorf("skicka: %s: %v", fn, err))
		}

		_, err = io.Copy(os.Stdout, contentsReader)
		contentsReader.Close()
		if err != nil {
			printErrorAndExit(fmt.Errorf("skicka: %s: %v", fn, err))
		}
	}
}
