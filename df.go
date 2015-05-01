//
// df.go
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
	"os"
	"strings"
)

func df(args []string) int {
	if len(args) != 0 {
		fmt.Printf("Usage: skicka df\n")
		fmt.Printf("Run \"skicka help\" for more detailed help text.\n")
		return 1
	}

	info, err := gd.GetDriveUsage()
	if err != nil {
		fmt.Fprintf(os.Stderr, "skicka: %s\n", err)
		return 1
	}

	dfItem("Capacity", info.Capacity, 0)
	sumUsed := int64(0)
	for _, u := range info.Users {
		dfItem(u.Name, u.Used, info.Capacity)
		sumUsed += u.Used
	}
	dfItem("Free space", info.Capacity-sumUsed, info.Capacity)
	return 0
}

func dfItem(s string, n, total int64) {
	s = strings.ToUpper(s[0:1]) + strings.ToLower(s[1:])
	if total != 0 {
		fmt.Printf("%-10s %s    %5.2f%%\n", s, fmtbytes(n, true),
			100.*float64(n)/float64(total))
	} else {
		fmt.Printf("%-10s %s\n", s, fmtbytes(n, true))
	}
}
