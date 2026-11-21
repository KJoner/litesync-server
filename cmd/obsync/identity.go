package main

// obsync identity / obsync vaults：统一身份与仓库初始化的 SSH 兜底（v0.20 公开化）。
//
//	obsync identity link --user <user_id> --issuer <iss> --subject <sub>
//	    把一个外部身份（OIDC 的 iss + sub）绑定到已有本地用户。用于网页认领走不通时
//	   （旧管理员 Token 丢失等）。shell 权限即最终授权（与 `obsync token reset` 同级）；
//	    冲突一律拒绝，从不覆盖已有映射（ADR-011 I-2/I-3）。
//	obsync identity list
//	    列出全部外部身份映射（不含任何秘密；邮箱只显示脱敏形式）。
//	obsync vaults pending
//	    列出尚未完成加密初始化的仓库（升级回滚前必须先处理它们：旧版本不会拦截它们的明文写入，见迁移方案 M2）。

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

func openDataDB() (*sql.DB, error) {
	dataDir := os.Getenv("OBSYNC_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	dbPath := filepath.Join(dataDir, "sync.db")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("database not found at %s (set OBSYNC_DATA_DIR): %w", dbPath, err)
	}
	return db.Open(dbPath)
}

func maskEmail(e string) string {
	at := strings.IndexByte(e, '@')
	if at <= 1 {
		return e
	}
	return e[:1] + strings.Repeat("*", at-1) + e[at:]
}

func runIdentity(args []string) error {
	if len(args) == 0 {
		fmt.Println(`用法：
  obsync identity link --user <user_id> --issuer <iss> --subject <sub>
  obsync identity list`)
		return nil
	}
	h, err := openDataDB()
	if err != nil {
		return err
	}
	defer h.Close()
	switch args[0] {
	case "list":
		rows, err := h.Query(`SELECT issuer, subject, user_id, email, email_verified, last_login_at FROM external_identities ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var iss, sub, uid, email string
			var verified int
			var last int64
			if err := rows.Scan(&iss, &sub, &uid, &email, &verified, &last); err != nil {
				return err
			}
			fmt.Printf("%-16s %-40s %s  %s (verified=%v) last=%s\n", uid, iss, sub, maskEmail(email), verified == 1, time.Unix(last, 0).Format(time.RFC3339))
		}
		return rows.Err()
	case "link":
		var user, iss, sub string
		for i := 1; i < len(args); i++ {
			if i+1 >= len(args) {
				return fmt.Errorf("参数 %s 缺少值", args[i])
			}
			switch args[i] {
			case "--user":
				user = args[i+1]
			case "--issuer":
				iss = args[i+1]
			case "--subject":
				sub = args[i+1]
			default:
				return fmt.Errorf("未知参数：%s", args[i])
			}
			i++
		}
		if user == "" || iss == "" || sub == "" {
			return errors.New("--user、--issuer、--subject 都必须提供")
		}
		u, err := db.GetUser(h, user)
		if err != nil {
			return err
		}
		if u == nil {
			return fmt.Errorf("本地用户 %s 不存在", user)
		}
		if err := db.LinkIdentity(h, iss, sub, user, db.IdentityProfile{}, time.Now().Unix()); err != nil {
			if errors.Is(err, db.ErrIdentityTaken) {
				return errors.New("这个外部身份已绑定到另一个本地用户；为防误合并，CLI 也不会覆盖")
			}
			if errors.Is(err, db.ErrUserAlreadyLinked) {
				return errors.New("该本地用户在这个 issuer 下已绑定了另一个主体")
			}
			return err
		}
		_ = db.AuditUserEvent(h, user, "identity-linked", "via=cli issuer="+iss) //nolint:errcheck
		fmt.Printf("已把 %s 的主体绑定到本地用户 %s（下次用统一账号登录即进入该账号）\n", iss, user)
		return nil
	default:
		return fmt.Errorf("未知子命令：identity %s", args[0])
	}
}

func runVaults(args []string) error {
	if len(args) == 0 || args[0] != "pending" {
		fmt.Println(`用法：
  obsync vaults pending   列出尚未完成加密初始化的仓库`)
		return nil
	}
	h, err := openDataDB()
	if err != nil {
		return err
	}
	defer h.Close()
	list, err := db.ListPendingVaults(h)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("没有未完成初始化的仓库。")
		return nil
	}
	for _, v := range list {
		lease := "无租约"
		if v.LeaseExpires > 0 {
			lease = "租约至 " + time.Unix(v.LeaseExpires, 0).Format(time.RFC3339)
		}
		fmt.Printf("%s  %s  version=%d  %s\n", v.VaultID, v.State, v.Version, lease)
	}
	fmt.Println("\n这些仓库没有任何内容（未就绪的仓库拒绝一切写入）；可以让用户在网页上完成设置，或由用户删除。")
	return nil
}
