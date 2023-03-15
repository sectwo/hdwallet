package main

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	HardenedKeyStart = 0x80000000 // 2^31
)

func DeriveKeyFromPath(masterKey *Key, path string) (*Key, error) {
	var indexes []uint32
	keys := []string{"Purpose", "CoinType", "Account", "Change", "AccountIndex"}
	segments := strings.Split(path, "/")
	if len(segments) == 0 || segments[0] != "m" {
		return nil, fmt.Errorf("invalid path")
	}

	for _, segment := range segments[1:] {
		segment = strings.TrimRight(segment, "'")
		index, err := strconv.Atoi(segment)
		if err != nil {
			return nil, fmt.Errorf("invalid path segment: %s", segment)
		}
		indexes = append(indexes, uint32(index))
	}

	if len(indexes) != 5 {
		return nil, fmt.Errorf("invalid path")
	}

	pathIndex := make(map[string]uint32)
	for i, k := range keys {
		pathIndex[k] = indexes[i]
	}

	purpose, _ := masterKey.NewChildKey(pathIndex["Purpose"] + HardenedKeyStart)
	coinType, _ := purpose.NewChildKey(pathIndex["CoinType"] + HardenedKeyStart)
	account, _ := coinType.NewChildKey(pathIndex["Account"] + HardenedKeyStart)
	change, _ := account.NewChildKey(pathIndex["Change"])
	child, _ := change.NewChildKey(pathIndex["AccountIndex"])

	return child, nil
}
