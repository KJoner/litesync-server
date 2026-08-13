package sync

// 改名（协议 v6 / ADR-001 §3.4）。
//
// v5 的 MOVE 是「旧路径 tombstone + 新路径新行」：历史断成两截、
// 身份被换掉、还留下一条假删除。v6 里身份不再依赖 path，于是改名退化为
// **一次元数据更新**：
//
//	UPDATE file_heads SET pseudonym = ?, canonical_path_hmac = ?, meta_generation = +1
//
// 内容 blob、revision、contentGeneration 全部不动，**不产生任何 tombstone**。
// changes 里发布一条 hash 未变但 metaGeneration 变新的记录，客户端据此做本地 rename。
//
// 这同时消灭了 v0.12.1 里「迁移必然留下明文 tombstone 因而无法 complete」的死结。

import (
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
)

type RenameResult struct {
	FileID         string
	FromPseudonym  string
	ToPseudonym    string
	Revision       int64
	MetaGeneration int64
	Sequence       int64
}

// RenameParams 改名参数。
type RenameParams struct {
	FromPseudonym string
	ToPseudonym   string
	// BaseMetaGeneration：元数据 CAS。并发改名时落后的一方拿到 412 后重取再试
	BaseMetaGeneration int64
	// MetaEnc / CanonicalHash：meta-encrypted 态下必带（真实路径在密文里）
	MetaEnc       string
	CanonicalHash string
	DeviceID      string
	// Client：逐请求协议/世代上下文（含幂等键）
	Client ClientContext
}

// Rename 执行改名（元数据更新）。
func (s *Service) Rename(p RenameParams) (*RenameResult, error) {
	if err := storage.ValidatePath(p.FromPseudonym); err != nil {
		return nil, err
	}
	if err := storage.ValidatePath(p.ToPseudonym); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db, s.scope())
	if err != nil {
		return nil, err
	}
	if err := s.guardWrite(rs, p.Client, p.DeviceID, p.FromPseudonym); err != nil {
		return nil, err
	}

	// 状态守卫（v0.12.1 LS-121-S03 延续到 v6）：plain 状态下加密元数据没有任何
	// 合法来源，放行等于允许用特制请求污染元数据语义（例如伪造 canonical 键顶名）。
	// migrating 期间是混合态：伪名化过的对象需要携带元数据，因此这里放行。
	if rs.MetaState == db.MetaPlain && p.MetaEnc != "" {
		return nil, ErrEncryptionState
	}
	metaMode := rs.MetaState == db.MetaEncrypted || rs.MetaState == db.MetaVerifying
	if metaMode {
		// 伪名寻址下「改名」只改加密元数据，服务器可见的 pseudonym 不变
		if p.FromPseudonym != p.ToPseudonym {
			return nil, ErrMetaRequired
		}
		if p.MetaEnc == "" || p.CanonicalHash == "" {
			return nil, ErrMetaRequired
		}
	}

	cur, err := db.GetHeadByPseudonym(s.db, p.FromPseudonym)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, ErrNotFound
	}
	if cur.MetaGeneration != p.BaseMetaGeneration {
		return nil, ErrMetaCAS
	}

	// 幂等：同一 operationId 已提交过 → 返回那次结果
	if p.Client.OperationID != "" {
		if prev, err := db.FindChangeByOperation(s.db, cur.FileID, p.Client.OperationID); err != nil {
			return nil, err
		} else if prev != nil {
			return &RenameResult{
				FileID: cur.FileID, FromPseudonym: p.FromPseudonym, ToPseudonym: prev.Pseudonym,
				Revision: prev.Revision, MetaGeneration: prev.MetaGeneration, Sequence: prev.Sequence,
			}, nil
		}
	}

	canonicalKey := storage.CanonicalKey(p.ToPseudonym)
	if p.CanonicalHash != "" {
		canonicalKey = "h:" + p.CanonicalHash
	}

	if !metaMode && p.ToPseudonym != p.FromPseudonym {
		// 先查「目标名被占用」再查归一化碰撞：前者能给出对方的 revision/hash，
		// 客户端可以直接据此走冲突流程；后者只能说「有个东西挡着」
		if occupied, err := db.GetHeadByPseudonym(s.db, p.ToPseudonym); err != nil {
			return nil, err
		} else if occupied != nil {
			return nil, &ConflictError{Path: p.ToPseudonym, Revision: occupied.Revision,
				Hash: occupied.ContentHash, FileID: occupied.FileID}
		}
		// 目标名上只有 tombstone？允许改名（0.17 实测反馈修正）。
		//
		// 「防复活」（ADR-002 / INV-06）保护的是**内容**：base-0 上传不得把
		// 已删除对象的旧内容悄悄带回仓库。把另一个 live 对象改名到这个名字
		// 不是复活——没有任何已删内容回来，删除事实（tombstone，按 fileId
		// 记账）原样保留：死对象的显式 restore 会因名字被占而明确 409，
		// 此名上的后续 base-0 上传撞的是 live 对象的冲突，同样不静默。
		//
		// 以前这里 409「必须走 restore」，客户端只能退化为 delete+upsert；
		// upsert 又撞墓碑走 restore，把改名的内容**嫁接到死对象的身份上**——
		// 用户看到的是「改名后历史没被继承」（继承的是别人的坟墓）。
	}
	// 目标名与别的 live 对象归一化后同名 → 422（排除自己，允许纯大小写改名）
	if other, err := db.FindCanonicalCollision(s.db, canonicalKey, cur.FileID); err != nil {
		return nil, err
	} else if other != "" {
		return nil, &PathCollisionError{Path: p.ToPseudonym, Existing: other}
	}

	now := time.Now().Unix()
	newMetaGen := cur.MetaGeneration + 1

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	head := *cur
	head.Pseudonym = p.ToPseudonym
	head.CanonicalPathHmac = canonicalKey
	head.MetaGeneration = newMetaGen
	head.UpdatedAt = now
	if p.MetaEnc != "" {
		head.EncryptedMetadata = p.MetaEnc
	}
	if err := db.UpsertHead(tx, &head); err != nil {
		return nil, err
	}
	// 内容未变：revision 与 contentGeneration 原样保留（INV-05）
	seq, err := db.InsertChange(tx, &db.ObjectChange{
		FileID: head.FileID, Action: "upsert", Revision: head.Revision,
		ContentGeneration: head.ContentGeneration, MetaGeneration: newMetaGen,
		Pseudonym: head.Pseudonym, ContentHash: head.ContentHash,
		OperationID: p.Client.OperationID, CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.log.Info("rename", "fileId", truncateID(head.FileID), "metaGen", newMetaGen, "device", p.DeviceID)
	return &RenameResult{
		FileID: head.FileID, FromPseudonym: p.FromPseudonym, ToPseudonym: head.Pseudonym,
		Revision: head.Revision, MetaGeneration: newMetaGen, Sequence: seq,
	}, nil
}
