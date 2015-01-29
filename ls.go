package main

import (
	"fmt"
	"github.com/google/skicka/gdrive"
	"google.golang.org/api/drive/v2"
	"path/filepath"
	"sort"
	"time"
)

func getPermissionsAsString(driveFile *drive.File) (string, error) {
	var str string
	if gdrive.IsFolder(driveFile) {
		str = "d"
	} else {
		str = "-"
	}

	perm, err := getPermissions(driveFile)
	if err != nil {
		str += "?????????"
	} else {
		rwx := "rwx"
		for i := 0; i < 9; i++ {
			if perm&(1<<(8-uint(i))) != 0 {
				str += string(rwx[i%3])
			} else {
				str += "-"
			}
		}
	}
	return str, nil
}

func Ls(args []string) {
	long := false
	longlong := false
	recursive := false
	var drivePath string
	for _, value := range args {
		switch {
		case value == "-l":
			long = true
		case value == "-ll":
			longlong = true
		case value == "-r":
			recursive = true
		case drivePath == "":
			drivePath = value
		default:
			printUsageAndExit()
		}
	}

	if drivePath == "" {
		drivePath = "/"
	}
	drivePath = filepath.Clean(drivePath)

	includeBase := false
	mustExist := true
	existingFiles, err := gd.GetFilesUnderFolder(drivePath, recursive, includeBase,
		mustExist)
	if err != nil {
		printErrorAndExit(fmt.Errorf("skicka: %v", err))
	}

	var filenames []string
	for f := range existingFiles {
		filenames = append(filenames, f)
	}
	sort.Strings(filenames)

	for _, f := range filenames {
		file := existingFiles[f]
		printFilename := f
		if !recursive {
			printFilename = filepath.Base(f)
		}
		if gdrive.IsFolder(file) {
			printFilename += "/"
		}
		if long || longlong {
			synctime, _ := gdrive.GetModificationTime(file)
			permString, _ := getPermissionsAsString(file)
			if longlong {
				md5 := file.Md5Checksum
				if len(md5) != 32 {
					md5 = "--------------------------------"
				}
				fmt.Printf("%s  %s  %s  %s  %s\n", permString,
					fmtbytes(file.FileSize, true), md5,
					synctime.Format(time.ANSIC), printFilename)
				if debug {
					fmt.Printf("\t[ ")
					for _, prop := range file.Properties {
						fmt.Printf("%s: %s, ", prop.Key,
							prop.Value)
					}
					fmt.Printf("id: %s ]\n", file.Id)
				}
			} else {
				fmt.Printf("%s  %s  %s  %s\n", permString,
					fmtbytes(file.FileSize, true),
					synctime.Format(time.ANSIC), printFilename)
			}
		} else {
			fmt.Printf("%s\n", printFilename)
		}
	}
}
