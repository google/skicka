//
// gdrive.go
// Copyright(c)2014-2015 Google, Inc.
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

// Package gdrive provides a slightly higher-level API for Google Drive
// than is provided by the official Google Drive API Go language bindings.
// In addition to handling transient network errors, rate limit
// errors, and other http miscellania, gdrive also provides functionality
// for limiting bandwidth consumption in both uploads and downloads.
//
// gdrive was written to be independent of the skicka application; issues
// like encryption, mapping Google Drive files to Unix file semantics,
// etc., are intentionally not included here.
package gdrive

import (
	"google.golang.org/api/drive/v2"
	"testing"
)

func TestGetSorted(t *testing.T) {
	f := newFiles()
	f.Add("aaa", &drive.File{Title: "aaa"})
	f.Add("c", &drive.File{Title: "c"})
	f.Add("b", &drive.File{Title: "b"})
	f.Add("aaa", &drive.File{Title: "aaa"})
	f.Add("b", &drive.File{Title: "b"})
	f.Add("z", &drive.File{Title: "z"})

	files := f.GetSorted()

	expected := []string("aaa", "aaa", "b", "b", "c", "z")
	if len(files) != len(expected) {
		t.Fatalf("Expected %d sorted files, got %v", len(expected), len(files))
	}
	for i, s := range expected {
		if files[i].Path != expected[i] || files[i].File.Title != expected[i] {
			t.Fatalf("Expected \"%s\" for %d'th sorted file, got %v", expected[i],
				i, files[i])
		}
	}
}

func TestGetSortedUnique(t *testing.T) {
	f := newFiles()
	f.Add("aaa", &drive.File{Title: "aaa"})
	f.Add("c", &drive.File{Title: "c"})
	f.Add("b", &drive.File{Title: "b"})
	f.Add("aaa", &drive.File{Title: "aaa"})
	f.Add("b", &drive.File{Title: "b"})
	f.Add("z", &drive.File{Title: "z"})

	files, dupes := f.GetSortedUnique()
	if len(files) != 2 {
		t.Fatalf("Expected 2 unique files, got %v", len(files))
	}
	if files[0].Path != "c" || files[0].File.Title != "c" {
		t.Fatalf("Expected \"c\" for first sorted file, got %v", files[0])
	}
	if files[1].Path != "z" || files[1].File.Title != "z" {
		t.Fatalf("Expected \"c\" for first sorted file, got %v", files[1])
	}

	if len(dupes) != 2 {
		t.Fatalf("Expected 2 duplicated files, got %v", len(dupes))
	}
	if dupes[0] != "aaa" {
		t.Fatalf("Expected \"aaa\" for first dupe, got %s", dupes[0])
	}
	if dupes[1] != "b" {
		t.Fatalf("Expected \"b\" for first dupe, got %s", dupes[1])
	}

}
