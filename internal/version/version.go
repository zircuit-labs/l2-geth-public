// Copyright 2022 The go-ethereum Authors
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

// Package version implements reading of build version information.
package version

import (
	"fmt"
	"runtime"

	"github.com/zircuit-labs/l2-geth/params"
)

const ourPath = "github.com/zircuit-labs/l2-geth" // Path to our module

// ClientName creates a software name/version identifier according to common
// conventions in the Ethereum p2p network.
func ClientName(clientIdentifier string) string {
	return fmt.Sprintf("%s/%v/%v",
		clientIdentifier,
		params.VersionWithMeta,
		runtime.GOARCH,
	)
}

// runtimeInfo returns build and platform information about the current binary.
//
// If the package that is currently executing is a prefixed by our go-ethereum
// module path, it will print out commit and date VCS information. Otherwise,
// it will assume it's imported by a third-party and will return the imported
// version and whether it was replaced by another module.
func Info() (version, vcs string) {
	version = params.VersionWithMeta
	return fmt.Sprintf("zircuit-l2geth %s", version), ""
}
