package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type directDaxCPUFeatureSet struct {
	clflush    bool
	clflushopt bool
	clwb       bool
}

type directDaxCacheInstruction uint8

const (
	directDaxCacheUnavailable directDaxCacheInstruction = iota
	directDaxCacheCLFlush
	directDaxCacheCLFlushOpt
	directDaxCacheCLWB
)

var (
	directDaxCPUFeaturesOnce sync.Once
	directDaxCPUFeatures     directDaxCPUFeatureSet
	directDaxCPUFeaturesErr  error
)

func currentDirectDaxCPUFeatures() (directDaxCPUFeatureSet, error) {
	directDaxCPUFeaturesOnce.Do(func() {
		data, err := os.ReadFile("/proc/cpuinfo")
		if err != nil {
			directDaxCPUFeaturesErr = fmt.Errorf("read CPU features: %w", err)
			return
		}
		directDaxCPUFeatures = parseDirectDaxCPUFeatures(string(data))
	})
	return directDaxCPUFeatures, directDaxCPUFeaturesErr
}

func parseDirectDaxCPUFeatures(cpuInfo string) directDaxCPUFeatureSet {
	features := directDaxCPUFeatureSet{}
	for _, line := range strings.Split(cpuInfo, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "flags" && key != "Features" {
			continue
		}
		for _, flag := range strings.Fields(value) {
			switch flag {
			case "clflush":
				features.clflush = true
			case "clflushopt":
				features.clflushopt = true
			case "clwb":
				features.clwb = true
			}
		}
	}
	return features
}

func selectDirectDaxWritebackInstruction(features directDaxCPUFeatureSet) directDaxCacheInstruction {
	switch {
	case features.clwb:
		return directDaxCacheCLWB
	case features.clflushopt:
		return directDaxCacheCLFlushOpt
	case features.clflush:
		return directDaxCacheCLFlush
	default:
		return directDaxCacheUnavailable
	}
}

func selectDirectDaxInvalidateInstruction(features directDaxCPUFeatureSet) directDaxCacheInstruction {
	switch {
	case features.clflushopt:
		return directDaxCacheCLFlushOpt
	case features.clflush:
		return directDaxCacheCLFlush
	default:
		return directDaxCacheUnavailable
	}
}
