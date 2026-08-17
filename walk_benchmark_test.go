// Copyright © 2026 Peter Haag peter@people.ops-trust.net
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package nfdump

import (
	"context"
	"os"
	"testing"
)

// Set NFDUMP_BENCH_V2 and NFDUMP_BENCH_V3 to representative 1.7.x and 1.8.x
// files to compare the two transparent Walk backends. Opening and closing are
// excluded so the result measures block decoding and callback delivery.
func BenchmarkWalkV2Count(b *testing.B) { benchmarkWalkFile(b, os.Getenv("NFDUMP_BENCH_V2"), false) }
func BenchmarkWalkV2GenericIP(b *testing.B) {
	benchmarkWalkFile(b, os.Getenv("NFDUMP_BENCH_V2"), true)
}
func BenchmarkWalkV3Count(b *testing.B) { benchmarkWalkFile(b, os.Getenv("NFDUMP_BENCH_V3"), false) }
func BenchmarkWalkV3GenericIP(b *testing.B) {
	benchmarkWalkFile(b, os.Getenv("NFDUMP_BENCH_V3"), true)
}

func benchmarkWalkFile(b *testing.B, path string, accessFields bool) {
	if path == "" {
		b.Skip("set the matching NFDUMP_BENCH_V2 or NFDUMP_BENCH_V3 fixture path")
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Skip(err)
	}
	b.ReportAllocs()
	b.SetBytes(info.Size())
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		nf := New()
		if err := nf.Open(path); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		count := 0
		err := nf.Walk(context.Background(), func(record FlowRecord) error {
			count++
			if accessFields {
				_, _ = record.Generic()
				_, _, _ = record.IP()
			}
			return nil
		})
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		if count == 0 {
			b.Fatal("fixture contains no flow records")
		}
		if err := nf.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
