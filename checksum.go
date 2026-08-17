// Copyright © 2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"github.com/zeebo/xxh3"
)

// v3Checksum64 is the checksum used by the V3 file directory and data
// blocks. nfdump 1.8.x computes it with XXH3_64bits (the default-secret,
// unseeded 64-bit variant of XXH3) - not classic XXH64, despite the on-disk
// field being named "xxHash". XXH3 is intricate enough (size-dependent code
// paths, a 192-byte default secret, stripe accumulation for large inputs)
// that a hand-rolled reimplementation is a poor trade against a checksum
// silently going wrong, so this delegates to the well-tested zeebo/xxh3
// package rather than vendoring a local copy the way xxHash64 used to be.
func v3Checksum64(data []byte) uint64 {
	return xxh3.Hash(data)
}
