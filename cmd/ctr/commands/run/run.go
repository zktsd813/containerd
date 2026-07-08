/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package run

import (
	gocontext "context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/console"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/cmd/ctr/commands/tasks"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/defaults"
	clabels "github.com/containerd/containerd/labels"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	gocni "github.com/containerd/go-cni"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func withMounts(context *cli.Context) oci.SpecOpts {
	return func(ctx gocontext.Context, client oci.Client, container *containers.Container, s *specs.Spec) error {
		mounts := make([]specs.Mount, 0)
		for _, mount := range context.StringSlice("mount") {
			m, err := parseMountFlag(mount)
			if err != nil {
				return err
			}
			mounts = append(mounts, m)
		}
		return oci.WithMounts(mounts)(ctx, client, container, s)
	}
}

// parseMountFlag parses a mount string in the form "type=foo,source=/path,destination=/target,options=rbind:rw"
func parseMountFlag(m string) (specs.Mount, error) {
	mount := specs.Mount{}
	r := csv.NewReader(strings.NewReader(m))

	fields, err := r.Read()
	if err != nil {
		return mount, err
	}

	for _, field := range fields {
		v := strings.SplitN(field, "=", 2)
		if len(v) < 2 {
			return mount, fmt.Errorf("invalid mount specification: expected key=val")
		}

		key := v[0]
		val := v[1]
		switch key {
		case "type":
			mount.Type = val
		case "source", "src":
			mount.Source = val
		case "destination", "dst":
			mount.Destination = val
		case "options":
			mount.Options = strings.Split(val, ":")
		default:
			return mount, fmt.Errorf("mount option %q not supported", key)
		}
	}

	return mount, nil
}

func resolveTrenvActionSubpath(root string) (string, error) {
	clean := filepath.Clean(root)
	relative := strings.TrimPrefix(clean, string(os.PathSeparator))
	if relative == "" || relative == "." {
		return "", fmt.Errorf("invalid action root %q", root)
	}
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == ".." {
			return "", fmt.Errorf("invalid action root %q", root)
		}
	}
	return relative, nil
}

func copyTrenvFile(source, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(target, mode.Perm())
}

func copyTrenvActionTree(source, target string) error {
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		targetPath := target
		if relative != "." {
			targetPath = filepath.Join(target, relative)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return err
			}
			return os.Symlink(linkTarget, targetPath)
		}
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode().Perm())
		}
		if info.Mode().IsRegular() {
			return copyTrenvFile(path, targetPath, info.Mode())
		}
		if path == source && !sourceInfo.IsDir() {
			return copyTrenvFile(path, targetPath, info.Mode())
		}
		return nil
	})
}

func stageTrenvActionRoots(ctx gocontext.Context, id, sourceRootfs string, rebinds []string) error {
	sourceRootfs = strings.TrimSpace(sourceRootfs)
	if sourceRootfs == "" || len(rebinds) == 0 {
		return nil
	}
	namespaceValue, ok := namespaces.Namespace(ctx)
	if !ok || strings.TrimSpace(namespaceValue) == "" {
		namespaceValue = "default"
	}
	targetRootfs := filepath.Join(defaults.DefaultStateDir, "io.containerd.runtime.v2.task", namespaceValue, id, "rootfs")
	for _, rebind := range rebinds {
		sourceRoot, targetRoot, ok := strings.Cut(strings.TrimSpace(rebind), ":")
		if !ok {
			return fmt.Errorf("invalid TrEnv action rebind %q", rebind)
		}
		sourceRelative, err := resolveTrenvActionSubpath(sourceRoot)
		if err != nil {
			return err
		}
		targetRelative, err := resolveTrenvActionSubpath(targetRoot)
		if err != nil {
			return err
		}
		sourcePath := filepath.Join(sourceRootfs, sourceRelative)
		targetPath := filepath.Join(targetRootfs, targetRelative)
		if err := copyTrenvActionTree(sourcePath, targetPath); err != nil {
			return fmt.Errorf("stage TrEnv action root %q -> %q: %w", sourcePath, targetPath, err)
		}
	}
	return nil
}

// Command runs a container
var Command = cli.Command{
	Name:           "run",
	Usage:          "run a container",
	ArgsUsage:      "[flags] Image|RootFS ID [COMMAND] [ARG...]",
	SkipArgReorder: true,
	Flags: append([]cli.Flag{
		cli.BoolFlag{
			Name:  "rm",
			Usage: "remove the container after running, cannot be used with --detach",
		},
		cli.BoolFlag{
			Name:  "null-io",
			Usage: "send all IO to /dev/null",
		},
		cli.StringFlag{
			Name:  "log-uri",
			Usage: "log uri",
		},
		cli.BoolFlag{
			Name:  "detach,d",
			Usage: "detach from the task after it has started execution, cannot be used with --rm",
		},
		cli.StringFlag{
			Name:  "fifo-dir",
			Usage: "directory used for storing IO FIFOs",
		},
		cli.StringFlag{
			Name:  "cgroup",
			Usage: "cgroup path (To disable use of cgroup, set to \"\" explicitly)",
		},
		cli.StringFlag{
			Name:  "platform",
			Usage: "run image for specific platform",
		},
		cli.BoolFlag{
			Name:  "cni",
			Usage: "enable cni networking for the container",
		},
		cli.StringFlag{
			Name:  "restore-image-path",
			Usage: "restore task state from a local CRIU image directory",
		},
		cli.StringFlag{
			Name:  "trenv-action-source-rootfs",
			Usage: "TrEnv restore-only exported source rootfs used to stage packaged action files",
		},
		cli.StringSliceFlag{
			Name:  "trenv-action-rebind",
			Usage: "TrEnv restore-only packaged action source:target root to stage before task start",
		},
	}, append(platformRunFlags,
		append(append(commands.SnapshotterFlags, []cli.Flag{commands.SnapshotterLabels}...),
			commands.ContainerFlags...)...)...),
	Action: func(context *cli.Context) error {
		var (
			err error
			id  string
			ref string

			rm        = context.Bool("rm")
			tty       = context.Bool("tty")
			detach    = context.Bool("detach")
			config    = context.IsSet("config")
			enableCNI = context.Bool("cni")
		)

		if config {
			id = context.Args().First()
			if context.NArg() > 1 {
				return errors.New("with spec config file, only container id should be provided")
			}
		} else {
			id = context.Args().Get(1)
			ref = context.Args().First()

			if ref == "" {
				return errors.New("image ref must be provided")
			}
		}
		if id == "" {
			return errors.New("container id must be provided")
		}
		if rm && detach {
			return errors.New("flags --detach and --rm cannot be specified together")
		}
		start := time.Now()

		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()
		container, err := NewContainer(ctx, client, context)
		if err != nil {
			return err
		}
		if rm && !detach {
			defer container.Delete(ctx, containerd.WithSnapshotCleanup)
		}
		var con console.Console
		if tty {
			con = console.Current()
			defer con.Reset()
			if err := con.SetRaw(); err != nil {
				return err
			}
		}
		var network gocni.CNI
		if enableCNI {
			if network, err = gocni.New(gocni.WithDefaultConf); err != nil {
				return err
			}
		}

		opts := getNewTaskOpts(context)
		ioOpts := []cio.Opt{cio.WithFIFODir(context.String("fifo-dir"))}
		task, err := tasks.NewTask(ctx, client, container, context.String("checkpoint"), con, context.Bool("null-io"), context.String("log-uri"), ioOpts, opts...)
		if err != nil {
			return err
		}
		if context.String("restore-image-path") != "" {
			if err := stageTrenvActionRoots(ctx, id, context.String("trenv-action-source-rootfs"), context.StringSlice("trenv-action-rebind")); err != nil {
				return err
			}
		}

		var statusC <-chan containerd.ExitStatus
		if !detach {
			defer func() {
				if enableCNI {
					if err := network.Remove(ctx, commands.FullID(ctx, container), ""); err != nil {
						logrus.WithError(err).Error("network review")
					}
				}
				task.Delete(ctx)
			}()

			if statusC, err = task.Wait(ctx); err != nil {
				return err
			}
		}
		restoreTask := context.String("restore-image-path") != ""
		writePidFile := func() error {
			if context.IsSet("pid-file") {
				return commands.WritePidFile(context.String("pid-file"), int(task.Pid()))
			}
			return nil
		}
		setupCNI := func() error {
			netNsPath, err := getNetNSPath(ctx, task)
			if err != nil {
				return err
			}

			if _, err := network.Setup(ctx, commands.FullID(ctx, container), netNsPath); err != nil {
				return err
			}
			return nil
		}
		if !restoreTask {
			if err := writePidFile(); err != nil {
				return err
			}
			if enableCNI {
				if err := setupCNI(); err != nil {
					return err
				}
			}
		}
		if err := task.Start(ctx); err != nil {
			return err
		}
		if restoreTask {
			if err := writePidFile(); err != nil {
				return err
			}
			if enableCNI {
				if err := setupCNI(); err != nil {
					return err
				}
			}
		}

		latency := float64(time.Since(start).Microseconds()) / 1000.0
		log.G(ctx).Infof("run latency: %.3fms", latency)
		if detach {
			return nil
		}
		if tty {
			if err := tasks.HandleConsoleResize(ctx, task, con); err != nil {
				logrus.WithError(err).Error("console resize")
			}
		} else {
			sigc := commands.ForwardAllSignals(ctx, task)
			defer commands.StopCatch(sigc)
		}
		status := <-statusC
		code, _, err := status.Result()
		if err != nil {
			return err
		}
		if _, err := task.Delete(ctx); err != nil {
			return err
		}
		if code != 0 {
			return cli.NewExitError("", int(code))
		}
		return nil
	},
}

// buildLabel builds the labels from command line labels and the image labels
func buildLabels(cmdLabels, imageLabels map[string]string) map[string]string {
	labels := make(map[string]string)
	for k, v := range imageLabels {
		if err := clabels.Validate(k, v); err == nil {
			labels[k] = v
		} else {
			// In case the image label is invalid, we output a warning and skip adding it to the
			// container.
			logrus.WithError(err).Warnf("unable to add image label with key %s to the container", k)
		}
	}
	// labels from the command line will override image and the initial image config labels
	for k, v := range cmdLabels {
		labels[k] = v
	}
	return labels
}
