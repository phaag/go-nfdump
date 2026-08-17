// Copyright © 2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"encoding/binary"
	"math/bits"
)

// xxHash64 is the checksum used by the V3 file directory and data blocks.
// Keeping the small implementation local avoids another module dependency in
// the reader's hot path.
func xxHash64(data []byte) uint64 {
	const (
		prime1 uint64 = 11400714785074694791
		prime2 uint64 = 14029467366897019727
		prime3 uint64 = 1609587929392839161
		prime4 uint64 = 9650029242287828579
		prime5 uint64 = 2870177450012600261
	)
	round := func(acc, input uint64) uint64 {
		acc += input * prime2
		acc = bits.RotateLeft64(acc, 31)
		return acc * prime1
	}
	mergeRound := func(acc, value uint64) uint64 {
		acc ^= round(0, value)
		return acc*prime1 + prime4
	}

	index := 0
	var hash uint64
	if len(data) >= 32 {
		v1 := prime1
		v1 += prime2
		v2 := prime2
		v3 := uint64(0)
		v4 := uint64(0)
		v4 -= prime1
		limit := len(data) - 32
		for index <= limit {
			v1 = round(v1, binary.LittleEndian.Uint64(data[index:]))
			v2 = round(v2, binary.LittleEndian.Uint64(data[index+8:]))
			v3 = round(v3, binary.LittleEndian.Uint64(data[index+16:]))
			v4 = round(v4, binary.LittleEndian.Uint64(data[index+24:]))
			index += 32
		}
		hash = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) + bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		hash = mergeRound(hash, v1)
		hash = mergeRound(hash, v2)
		hash = mergeRound(hash, v3)
		hash = mergeRound(hash, v4)
	} else {
		hash = prime5
	}
	hash += uint64(len(data))
	for index+8 <= len(data) {
		k1 := round(0, binary.LittleEndian.Uint64(data[index:]))
		hash ^= k1
		hash = bits.RotateLeft64(hash, 27)*prime1 + prime4
		index += 8
	}
	if index+4 <= len(data) {
		hash ^= uint64(binary.LittleEndian.Uint32(data[index:])) * prime1
		hash = bits.RotateLeft64(hash, 23)*prime2 + prime3
		index += 4
	}
	for index < len(data) {
		hash ^= uint64(data[index]) * prime5
		hash = bits.RotateLeft64(hash, 11) * prime1
		index++
	}
	hash ^= hash >> 33
	hash *= prime2
	hash ^= hash >> 29
	hash *= prime3
	hash ^= hash >> 32
	return hash
}
