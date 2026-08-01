package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func vnextOwnerUnixSchedulerRoundTrip(
	t *testing.T,
	rpc *vnextOwnerRPC,
	requiredUID int64,
	request daemonRequest,
) execResponse {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	server, err := openDaemonUnixServer(
		filepath.Join(directory, "cxld.sock"),
		0o750,
		true,
		vnextOwnerUnixListenerPolicy{
			Role:                 vnextOwnerCallerScheduler,
			RequiredSchedulerUID: requiredUID,
		})
	if err != nil {
		t.Fatalf("open real Scheduler Unix socket: %v", err)
	}
	defer server.close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := server.listener.Accept()
		if acceptErr != nil {
			return
		}
		serveConnWithVNextOwnerGatewayPolicyLimits(
			conn, rpc, nil, server.policy,
			make(chan struct{}, 1), make(chan struct{}, 1),
			time.Second, time.Second)
	}()
	client, err := net.Dial("unix", server.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := writeFrame(client, body)
	responseBody, err := readFrame(client)
	_ = client.Close()
	if err != nil {
		t.Fatalf("write/read Scheduler Unix request: %v / %v", writeErr, err)
	}
	<-done
	var response execResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestVNextOwnerSchedulerUnixSocketUsesExactPeerUID(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "unix-auth-device", Size: 256 << 10,
	}})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	request := vnextOwnerGatewayTestInventoryDaemonRequest(
		t, "owner-0", 7, "unix-peer-credentials")

	allowed := vnextOwnerUnixSchedulerRoundTrip(
		t, rpc, int64(os.Getuid()), request)
	if !allowed.Ok || allowed.Operation != vnextOwnerRPCOperationInventory {
		t.Fatalf("exact Scheduler UID response = %#v", allowed)
	}

	wrongUID := int64(os.Getuid()) + 1
	if wrongUID > int64(^uint32(0)) {
		wrongUID = int64(os.Getuid()) - 1
	}
	denied := vnextOwnerUnixSchedulerRoundTrip(t, rpc, wrongUID, request)
	if denied.Ok || denied.ErrorCode != string(vnextOwnerServicePermissionDenied) ||
		denied.Operation != "unix-authentication" {
		t.Fatalf("wrong Scheduler UID response = %#v", denied)
	}

	unconfigured := vnextOwnerUnixSchedulerRoundTrip(
		t, rpc, vnextOwnerSchedulerUIDUnconfigured, request)
	if unconfigured.Ok ||
		unconfigured.ErrorCode != string(vnextOwnerServicePermissionDenied) {
		t.Fatalf("unconfigured Scheduler UID response = %#v", unconfigured)
	}
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
		t.Fatalf("Unix authentication test created %d transactions", count)
	}
}

func TestVNextOwnerUnixCallerPrincipalUsesExactPeerUID(t *testing.T) {
	for _, policy := range []vnextOwnerUnixListenerPolicy{
		vnextOwnerRuntimeUnixPolicy,
		{
			Role:                 vnextOwnerCallerScheduler,
			RequiredSchedulerUID: int64(os.Getuid()),
		},
	} {
		t.Run(policy.Role.String(), func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "peer.sock")
			listener, err := net.ListenUnix(
				"unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			result := make(chan struct {
				caller vnextOwnerCallerContext
				err    error
			}, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					result <- struct {
						caller vnextOwnerCallerContext
						err    error
					}{err: err}
					return
				}
				defer conn.Close()
				caller, err := policy.authenticateCaller(conn)
				result <- struct {
					caller vnextOwnerCallerContext
					err    error
				}{caller: caller, err: err}
			}()
			client, err := net.DialUnix(
				"unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			got := <-result
			if got.err != nil {
				t.Fatal(got.err)
			}
			wantPrincipal, err := vnextOwnerUnixPrincipal(policy.Role, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			if got.caller.Role != policy.Role || got.caller.Principal != wantPrincipal {
				t.Fatalf("Unix caller=%#v, want role=%s principal=%q",
					got.caller, policy.Role, wantPrincipal)
			}
		})
	}
}

func TestSchedulerControlUIDConfigurationHasNoMalformedFallback(t *testing.T) {
	const unsetName = "CXLD_TEST_SCHEDULER_UID_UNSET_91B9F52D"
	old, existed := os.LookupEnv(unsetName)
	_ = os.Unsetenv(unsetName)
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(unsetName, old)
		} else {
			_ = os.Unsetenv(unsetName)
		}
	})
	if got, err := envStrictInt64(unsetName, vnextOwnerSchedulerUIDUnconfigured); err != nil || got != vnextOwnerSchedulerUIDUnconfigured {
		t.Fatalf("unset UID = %d, %v", got, err)
	}

	const validName = "CXLD_TEST_SCHEDULER_UID_VALID_91B9F52D"
	t.Setenv(validName, "1001")
	if got, err := envStrictInt64(validName, -1); err != nil || got != 1001 {
		t.Fatalf("valid UID = %d, %v", got, err)
	}
	for name, value := range map[string]string{
		"empty":      "",
		"whitespace": " 1001",
		"text":       "scheduler",
		"overflow":   "9223372036854775808",
	} {
		t.Run(name, func(t *testing.T) {
			environment := "CXLD_TEST_SCHEDULER_UID_INVALID_" + name
			t.Setenv(environment, value)
			if _, err := envStrictInt64(environment, -1); err == nil {
				t.Fatalf("invalid UID %q used its fallback", value)
			}
		})
	}
	for _, uid := range []int64{-2, int64(^uint32(0)) + 1} {
		if err := validateVNextOwnerSchedulerControlUID(uid); err == nil {
			t.Fatalf("out-of-range UID %d was accepted", uid)
		}
	}
}

func TestRemoveStaleDaemonUnixSocketNeverDeletesOtherFileTypes(t *testing.T) {
	directory := t.TempDir()
	targets := map[string]func(string) error{
		"directory": func(path string) error { return os.Mkdir(path, 0o700) },
		"regular": func(path string) error {
			return os.WriteFile(path, []byte("preserve"), 0o600)
		},
		"symlink": func(path string) error { return os.Symlink("missing", path) },
	}
	for name, create := range targets {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name)
			if err := create(path); err != nil {
				t.Fatal(err)
			}
			if err := removeStaleDaemonUnixSocket(path); err == nil {
				t.Fatal("non-socket path was accepted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("non-socket path was removed: %v", err)
			}
		})
	}

	socketPath := filepath.Join(directory, "stale.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleDaemonUnixSocket(socketPath); err != nil {
		t.Fatalf("remove actual stale Unix socket: %v", err)
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale Unix socket remains: %v", err)
	}
}

func TestDaemonUnixServerCloseDoesNotRemoveReplacementPath(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "cxld.sock")
	server, err := openDaemonUnixServer(
		socketPath, 0o750, false, vnextOwnerRuntimeUnixPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(socketPath); err != nil {
		server.close()
		t.Fatal(err)
	}
	if err := os.WriteFile(socketPath, []byte("replacement"), 0o600); err != nil {
		server.close()
		t.Fatal(err)
	}
	server.close()
	contents, err := os.ReadFile(socketPath)
	if err != nil {
		t.Fatalf("replacement path was removed: %v", err)
	}
	if string(contents) != "replacement" {
		t.Fatalf("replacement contents = %q", contents)
	}
}

func TestControlSocketInheritsPrecreatedSetgidDirectoryGroup(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	server, err := openDaemonUnixServer(
		filepath.Join(directory, "cxld.sock"), 0o750, true,
		vnextOwnerUnixListenerPolicy{
			Role:                 vnextOwnerCallerScheduler,
			RequiredSchedulerUID: int64(os.Getuid()),
		})
	if err != nil {
		t.Fatal(err)
	}
	defer server.close()
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	socketInfo, err := os.Lstat(server.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	directoryStat := directoryInfo.Sys().(*syscall.Stat_t)
	socketStat := socketInfo.Sys().(*syscall.Stat_t)
	if directoryStat.Gid != socketStat.Gid {
		t.Fatalf("socket GID %d, directory GID %d", socketStat.Gid, directoryStat.Gid)
	}
}
