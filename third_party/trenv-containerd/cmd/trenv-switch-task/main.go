package main

import (
	"os"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvtask/switchtask"
)

func main() {
	os.Exit(switchtask.Run(os.Args[1:], os.Stdout, os.Stderr))
}
