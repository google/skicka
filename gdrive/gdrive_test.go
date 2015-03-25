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
	"testing"
)

func TestGetSorted(t *testing.T) {
	f := newFiles()
	f.add(&File{Path: "aaa"})
	f.add(&File{Path: "c"})
	f.add(&File{Path: "b"})
	f.add(&File{Path: "aaa"})
	f.add(&File{Path: "b"})
	f.add(&File{Path: "z"})

	files := f.GetSorted()

	expected := []string{"aaa", "aaa", "b", "b", "c", "z"}
	if len(files) != len(expected) {
		t.Fatalf("Expected %d sorted files, got %v", len(expected), len(files))
	}
	for i := range expected {
		if files[i].Path != expected[i] {
			t.Fatalf("Expected \"%s\" for %d'th sorted file, got %v", expected[i],
				i, files[i])
		}
	}
}

func TestGetSortedUnique(t *testing.T) {
	f := newFiles()
	f.add(&File{Path: "aaa"})
	f.add(&File{Path: "c"})
	f.add(&File{Path: "b"})
	f.add(&File{Path: "aaa"})
	f.add(&File{Path: "b"})
	f.add(&File{Path: "z"})

	files, dupes := f.GetSortedUnique()
	if len(files) != 2 {
		t.Fatalf("Expected 2 unique files, got %v: %v", len(files), files)
	}
	if files[0].Path != "c" {
		t.Fatalf("Expected \"c\" for first sorted file, got %v", files[0])
	}
	if files[1].Path != "z" {
		t.Fatalf("Expected \"c\" for first sorted file, got %v", files[1])
	}

	if len(dupes) != 2 {
		t.Fatalf("Expected 2 duplicated files, got %v", len(dupes))
	}
	if _, ok := dupes["aaa"]; !ok {
		t.Fatalf("Expected \"aaa\" in dupes.")
	}
	if _, ok := dupes["b"]; !ok {
		t.Fatalf("Expected \"b\" in dupes.")
	}

}
