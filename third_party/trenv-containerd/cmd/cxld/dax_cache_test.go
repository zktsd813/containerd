package main

import "testing"

func TestParseDirectDaxCPUFeatures(t *testing.T) {
	features := parseDirectDaxCPUFeatures("flags : fpu clflush clflushopt clwb avx2\n")
	if !features.clflush || !features.clflushopt || !features.clwb {
		t.Fatalf("missing parsed DAX cache feature: %#v", features)
	}
}

func TestSelectDirectDaxCacheInstructions(t *testing.T) {
	tests := []struct {
		name       string
		features   directDaxCPUFeatureSet
		writeback  directDaxCacheInstruction
		invalidate directDaxCacheInstruction
	}{
		{name: "clwb", features: directDaxCPUFeatureSet{clflush: true, clflushopt: true, clwb: true}, writeback: directDaxCacheCLWB, invalidate: directDaxCacheCLFlushOpt},
		{name: "clflushopt", features: directDaxCPUFeatureSet{clflush: true, clflushopt: true}, writeback: directDaxCacheCLFlushOpt, invalidate: directDaxCacheCLFlushOpt},
		{name: "clflush", features: directDaxCPUFeatureSet{clflush: true}, writeback: directDaxCacheCLFlush, invalidate: directDaxCacheCLFlush},
		{name: "unsupported", features: directDaxCPUFeatureSet{}, writeback: directDaxCacheUnavailable, invalidate: directDaxCacheUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := selectDirectDaxWritebackInstruction(test.features); got != test.writeback {
				t.Fatalf("writeback instruction=%d want=%d", got, test.writeback)
			}
			if got := selectDirectDaxInvalidateInstruction(test.features); got != test.invalidate {
				t.Fatalf("invalidate instruction=%d want=%d", got, test.invalidate)
			}
		})
	}
}
