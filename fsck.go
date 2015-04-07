//
// fsck.go
// Copyright(c)2015 Google, Inc.
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
	"strings"
	"time"
)

func fsck(args []string, metadataCacheFilename string) int {
	path := ""
	actuallyTrash := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--trash-duplicates" {
			actuallyTrash = true
		} else if path == "" {
			path = args[i]
		} else {
			fmt.Fprintf(os.Stderr, "Usage: skicka fsck [--trash-duplicates] [drive_path]\n")
			fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
			return 1
		}
	}
	if path == "" {
		path = "/"
	}

	if actuallyTrash {
		fmt.Fprintf(os.Stderr, `
**** WARNING WARNING DANGER ****

The "fsck" command is new and hasn't been thoroughly tested. In that
it will optionally delete files from Google Drive, you should be
very careful with it. At minimum, please first do a run without the
"--trash-duplicates" option tnd make sure that any files that it says
it's planning on deleting are ok to delete.

If disaster strikes and it deletes something it shouldn't (or if it
wants to delete something it shouldn't, please file a bug at
https://github.com/google/skicka/issues.) If it has made a deletion
mistake, it should be possible to salvage the file from the trash.

**** WARNING WARNING DANGER ****

`)
		time.Sleep(10 * time.Second)
	}

	includeBase := true
	files, err := gd.GetFilesUnderFolder(path, includeBase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skicka: %s: %v\n", path, err)
		return 1
	}

	errs := 0
	uniques, dupes := gdrive.PartitionUniquesAndMultiples(files)
	for _, f := range uniques {
		errs += checkFile(f)
	}
	for _, files := range dupes {
		errs += cleanupDupes(files, actuallyTrash)
	}

	// See if the metadata cache is in sync.
	gd.CheckMetadata(metadataCacheFilename, func(msg string) {
		fmt.Fprintf(os.Stderr, "skicka: %s\n", msg)
		errs++
	})

	return errs
}

func checkFile(f *gdrive.File) int {
	hasSuffix := strings.HasSuffix(f.Path, encryptionSuffix)
	_, err := f.GetProperty("IV")
	hasIV := err == nil

	if hasSuffix && !hasIV {
		fmt.Fprintf(os.Stderr, "skicka: %s: has filename suffix \"%s\" but no IV property\n",
			f.Path, encryptionSuffix)
		return 1
	} else if hasIV && !hasSuffix {
		fmt.Fprintf(os.Stderr, "skicka: %s: has IV property but no filename suffix \"%s\"\n",
			f.Path, encryptionSuffix)
		return 1
	}
	return 0
}

func cleanupDupes(files []*gdrive.File, actuallyTrash bool) int {
	if len(files) < 2 {
		panic(fmt.Sprintf("less than two files in dupes?: %d %v",
			len(files), files))
	}
	fmt.Fprintf(os.Stderr, "skicka: %s: found %d duplicates\n",
		files[0].Path, len(files))

	// If any of them are Google Apps files, then give up early; they all
	// come up with size equals zero and empty md5 strings.
	for _, f := range files {
		if f.IsGoogleAppsFile() {
			if f.FileSize > 0 || f.Md5 != "" {
				fmt.Fprintf(os.Stderr, "skicka: %s: surprise! Google Apps file "+
					"with mimetype %s has length %d and MD5 %s.\n", f.Path,
					f.MimeType, f.FileSize, f.Md5)
				return 0
			}
			fmt.Fprintf(os.Stderr, "skicka: %s: one or more are Google Apps files. "+
				"Can't compare their contents so leaving them as is.\n", f.Path)
			return 1
		}
	}

	errs := 0
	survivor := files[0]
	for i := 1; i < len(files); i++ {
		f := files[i]
		var err error
		// If this file is empty, then we can discard it: the survivor is
		// either also empty or actually has contents, so this file is
		// definitely less useful.
		if f.FileSize == 0 {
			err = deleteDupe(f, actuallyTrash)
		} else {
			// Not empty.
			if f.FileSize == survivor.FileSize && f.Md5 == survivor.Md5 {
				// Does it exactly match the survivor?  If so, we can
				// delete it.
				err = deleteDupe(f, actuallyTrash)
			} else if survivor.FileSize == 0 {
				// The survivor is empty but this file isn't.  Delete the
				// previous survivor and keep this one as the new survivor.
				err = deleteDupe(survivor, actuallyTrash)
				survivor = f
			} else {
				// Both this file and the survivor are non-empty, but they
				// differ, so don't do anything.
				fmt.Fprintf(os.Stderr, "skicka: %s: at least two instances of this file "+
					"are non-empty but have different contents. Leaving them alone.\n", f.Path)
				return 0
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "skicka: %s: %s\n", f.Path, err)
			errs++
		}
	}
	return errs
}

func deleteDupe(f *gdrive.File, actuallyTrash bool) error {
	if !actuallyTrash {
		fmt.Fprintf(os.Stderr, "skicka: %s[%s]: would trash (size %d md5 %s)\n",
			f.Path, f.Id, f.FileSize, f.Md5)
		return nil
	}

	fmt.Fprintf(os.Stderr, "skicka: %s[%s]: trashing (size %d md5 %s)\n",
		f.Path, f.Id, f.FileSize, f.Md5)
	// Store its original path in a property, just in case of disaster and
	// it's necessary to write a little restore tool.
	err := gd.AddProperty("Path", f.Path, f)
	if err != nil {
		return err
	}
	return gd.TrashFile(f)
}
