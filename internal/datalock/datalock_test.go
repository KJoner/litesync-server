package datalock

// 数据目录锁（复审 SV-03 的「源库停写」机器检查）：同一目录第二次取锁必须失败；释放后可以再取；
// 锁文件里有持锁者的诊断信息。覆盖 INV-11（迁移只在源库停写时进行，可重复、可续跑）。

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecondAcquireIsRefusedUntilRelease(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir, "test-server")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir, "test-migrate"); !errors.Is(err, ErrHeld) {
		t.Fatalf("second acquire = %v, want ErrHeld", err)
	}
	if h := Holder(dir); !strings.Contains(h, "purpose=test-server") {
		t.Fatalf("holder info = %q", h)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	l2, err := Acquire(dir, "test-migrate")
	if err != nil {
		t.Fatalf("acquire after release = %v", err)
	}
	l2.Release() //nolint:errcheck
}

// 跨进程：子进程持锁时父进程拿不到；子进程退出（不调用 Release）后锁自动释放。
func TestLockIsReleasedWhenTheHolderExits(t *testing.T) {
	if os.Getenv("DATALOCK_HELPER_DIR") != "" {
		if _, err := Acquire(os.Getenv("DATALOCK_HELPER_DIR"), "helper"); err != nil {
			os.Exit(3)
		}
		os.Stdout.WriteString("locked\n") //nolint:errcheck
		buf := make([]byte, 1)
		os.Stdin.Read(buf) //nolint:errcheck // 等父进程关掉 stdin，然后不释放直接退出
		os.Exit(0)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run", "TestLockIsReleasedWhenTheHolderExits")
	cmd.Env = append(os.Environ(), "DATALOCK_HELPER_DIR="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line := make([]byte, 7)
	if _, err := out.Read(line); err != nil || string(line[:6]) != "locked" {
		t.Fatalf("helper did not lock: %q %v", line, err)
	}
	if _, err := Acquire(dir, "parent"); !errors.Is(err, ErrHeld) {
		t.Fatalf("acquire while another process holds the lock = %v, want ErrHeld", err)
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
	l, err := Acquire(dir, "parent")
	if err != nil {
		t.Fatalf("lock must be released when the holder exits, got %v", err)
	}
	l.Release() //nolint:errcheck
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
}
