//go:build windows

package agent

import "fmt"

func RootFilesystemUsedBytes(string) (uint64, error) {
	return 0, fmt.Errorf("the probe agent only supports Linux")
}
