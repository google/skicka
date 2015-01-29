package main

import (
	"fmt"
	"github.com/google/skicka/gdrive"
	"path/filepath"
	"sort"
)

func Du(args []string) {
	if len(args) != 1 {
		printUsageAndExit()
	}
	drivePath := filepath.Clean(args[0])

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
			for ; dirName != "/"; dirName = filepath.Dir(dirName) {
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
