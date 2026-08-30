package main

// obsync token reset：API Token 重置的 SSH 兜底（v0.18 / v11 设计 §4.5）。
//
// 网页端的重置受 E2EE 重置凭证保护；这里刻意**不**受——有服务器 shell 的人
// 本来就能改任何东西，装样子的门禁只会耽误事故响应。它处理网页端救不了的场景：
//   - 攻击者抢注了重置凭证或抢先重置了 Token；
//   - 用户忘了 Token（网页也登不进去）。
//
// 与运行中的服务并发安全：认证与会话世代都是逐请求查库的，
// 改完库立即生效，不需要重启服务。

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KJoner/litesync-server/internal/db"
)

func runToken(args []string) error {
	if len(args) == 0 || args[0] != "reset" {
		fmt.Println(`用法：
  obsync token reset               为管理员生成新的 API Token（明文只打印这一次）
  obsync token reset --user <名>   为指定用户重置
  obsync token reset --from-env    把管理员 Token 重设为 OBSYNC_TOKEN 环境变量的值

重置会同时撤销该用户全部设备凭据并作废其全部网页会话。
每台设备之后只需在插件设置里填入新 Token → 点「测试连接」即可恢复，
本地数据、历史与端到端加密密钥都不受影响。`)
		return nil
	}

	var userName string
	fromEnv := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--user":
			i++
			if i >= len(args) {
				return errors.New("--user 需要一个用户名")
			}
			userName = args[i]
		case "--from-env":
			fromEnv = true
		default:
			return fmt.Errorf("未知参数：%s", args[i])
		}
	}

	dataDir := os.Getenv("OBSYNC_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	dbPath := filepath.Join(dataDir, "sync.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("database not found at %s (set OBSYNC_DATA_DIR): %w", dbPath, err)
	}
	database, err := db.Open(dbPath)
	if err != nil {
		return err
	}
	defer database.Close()

	var user *db.User
	if userName == "" {
		user, err = db.GetUser(database, db.AdminUserID)
	} else {
		user, err = db.GetUserByName(database, userName)
		if err == nil && user == nil {
			user, err = db.GetUser(database, userName) // 也接受直接给 user_id
		}
	}
	if err != nil {
		return err
	}
	if user == nil {
		if userName == "" {
			return errors.New("管理员账号尚未建立（服务从未启动过？先启动一次服务完成初始化）")
		}
		return fmt.Errorf("用户不存在：%s", userName)
	}

	vaultID, err := db.OwnerVaultOf(database, user.UserID)
	if err != nil {
		return err
	}
	if vaultID == "" {
		return fmt.Errorf("用户 %s 没有专属 Vault，数据不一致", user.UserID)
	}
	scope := db.ScopeFromAuth(vaultID)

	var token string
	if fromEnv {
		if user.UserID != db.AdminUserID {
			return errors.New("--from-env 只适用于管理员（普通用户没有环境变量 Token）")
		}
		token = os.Getenv("OBSYNC_TOKEN")
		if len(token) < 16 {
			return errors.New("OBSYNC_TOKEN 未设置或短于 16 字符")
		}
	} else {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		token = db.TokenPrefix + hex.EncodeToString(raw)
	}

	tx, err := database.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	gen, err := db.SetUserToken(tx, user.UserID, db.HashToken(token))
	if err != nil {
		return err
	}
	revoked, err := db.RevokeDevicesOfUser(tx, scope, user.UserID)
	if err != nil {
		return err
	}
	if err := db.AppendAudit(tx, scope, "cli:"+user.UserID, "token-reset",
		fmt.Sprintf("user=%s devices=%d generation=%d via=cli fromEnv=%v",
			user.UserID, revoked, gen, fromEnv)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if fromEnv {
		fmt.Println("管理员 Token 已重设为 OBSYNC_TOKEN 环境变量的值（数据库里只存哈希）。")
	} else {
		fmt.Printf("新的 API Token（明文只显示这一次，服务器只存哈希）：\n\n  %s\n\n", token)
	}
	fmt.Printf("已撤销该用户 %d 台设备的凭据；其全部网页会话已作废。\n", revoked)
	fmt.Println("每台设备：在插件设置里填入新 Token → 点「测试连接」即可恢复同步。")
	if !fromEnv && user.UserID == db.AdminUserID {
		fmt.Println("提醒：.env 里的 OBSYNC_TOKEN 从现在起无效（以数据库为准）；建议同步更新它，避免日后困惑。")
	}
	return nil
}
