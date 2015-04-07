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
	"sort"
	"testing"
)

func TestGetSortedUnique(t *testing.T) {
	var f []*File
	f = append(f, &File{Path: "aaa"})
	f = append(f, &File{Path: "c"})
	f = append(f, &File{Path: "b"})
	f = append(f, &File{Path: "aaa"})
	f = append(f, &File{Path: "b"})
	f = append(f, &File{Path: "z"})
	sort.Sort(byPath(f))

	files, dupes := PartitionUniquesAndMultiples(f)
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
