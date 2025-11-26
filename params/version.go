// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"encoding/json"
	"os"
	"time"

	"github.com/zircuit-labs/zkr-go-common/version"
)

var (
	Info            version.VersionInformation
	VersionWithMeta string
)

func init() {
	VersionWithMeta = "unknown-version"

	// Read the version information from the JSON file
	file, err := os.ReadFile("/etc/version.json")
	if err != nil {
		return
	}
	err = json.Unmarshal(file, &Info)
	if err != nil {
		return
	}
	Info.Date = time.Unix(Info.GitDate, 0).UTC()

	// Set the version with meta information
	VersionWithMeta = Info.Version

	// Add the variant to the version if it exists
	if Info.Variant != "" {
		VersionWithMeta += "-" + Info.Variant
	}
}
