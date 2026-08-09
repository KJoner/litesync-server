package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner 抽象 restic 子进程调用（业务层禁止直接 exec）。
// 凭据只经 env 传递，绝不进入 args；stderr 会被截断并脱敏后并入错误信息。
type Runner interface {
	Run(ctx context.Context, args []string, env map[string]string) (stdout []byte, err error)
}

// execRunner 是真实实现：每次备份 fork 一个 restic 进程，结束即退出，
// 不产生常驻内存占用。
type execRunner struct {
	bin string
}

// NewRunner 返回基于 exec 的 restic Runner。
func NewRunner(bin string) Runner {
	if bin == "" {
		bin = "restic"
	}
	return &execRunner{bin: bin}
}

func (r *execRunner) Run(ctx context.Context, args []string, env map[string]string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Env = os.Environ()
	secrets := make([]string, 0, len(env))
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
		if isSecretEnv(k) && v != "" {
			secrets = append(secrets, v)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("restic %s: %w: %s",
			args[0], err, redact(tail(stderr.String(), 2000), secrets))
	}
	return stdout.Bytes(), nil
}

func isSecretEnv(key string) bool {
	switch key {
	case "RESTIC_PASSWORD", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID":
		return true
	}
	return false
}

// redact 把已知 secret 值从文本中抹除（防御性兜底；正常情况 restic 不会回显）。
func redact(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
