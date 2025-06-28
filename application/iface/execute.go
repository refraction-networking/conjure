package iface

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Executor provides an interface for executing commands so that a mock can be created to test
// command generation without actually modifying the system.
type Executor interface {
	execute(program string, args []string) ([]byte, error)
}

type executor struct{}

func (ex *executor) execute(program string, args []string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("Can't Execute this on a windows machine")
	}
	out, err := exec.Command(program, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run command: %v", err)
	}

	return out, nil
}
