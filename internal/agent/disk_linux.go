//go:build linux

package agent

import (
	"fmt"
	"syscall"
)

func RootFilesystemUsedBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 || stat.Bavail > stat.Blocks {
		return 0, fmt.Errorf("invalid filesystem counters")
	}
	blocksUsed := stat.Blocks - stat.Bavail
	blockSize := uint64(stat.Bsize)
	if blocksUsed > ^uint64(0)/blockSize {
		return 0, fmt.Errorf("filesystem usage overflows uint64")
	}
	return blocksUsed * blockSize, nil
}
