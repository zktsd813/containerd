package main

import (
	"os"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvtask/checkpoint"
)

func main() {
	os.Exit(checkpoint.Run(os.Args[1:], os.Stdout, os.Stderr))
}
