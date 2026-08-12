package sync

// 元数据加密（v9.3 三期，协议 v5）。
//
// meta-encrypted 态下服务器彻底不知道文件路径：
//   - 可见 path = 32-hex 伪名（= file_id）；真实路径在 LSM1 加密的 meta_enc 里
//   - 改名 = 元数据更新（metaGeneration CAS），内容 blob 与内容 generation 不动
//   - 同名并存判定靠客户端 HMAC 的 canonical 键（服务器学不到路径内容）
//
// 迁移（plain → migrating → encrypted）：
//   - migrate-file：单事务把「真实路径行」搬到「伪名行」（file_id 继承、
//     内容零重加密——LSE3 的 AAD 绑 fileId 不绑路径，这是二期铺垫的直接收益），
//     并同步改写该文件历史版本的 path
//   - complete：验证全量伪名化后执行「明文路径抹除」：删除全部 tombstone 行、
//     清除无法再解密的旧信封（LSE1/LSE2）历史、全量裁剪 changes 并推进水位线
//     （旧 changes 里的明文路径随之消失；所有客户端下轮走 snapshot 对账）
//   - abort：停在混合态（已迁移的伪名行照常工作），不做任何破坏性操作
//
// 抹除是单向点：只发生在 complete，且要求调用方显式确认。

import (
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

type MetaUpdateResult struct {
	Path           string
	Revision       int64
	MetaGeneration int64
	Sequence       int64
}

// UpdateFileMeta 元数据更新（改名）：内容不动，metaGeneration CAS 后 +1，
// 发布一条 hash 不变但 metaGeneration 变新的 change（客户端据此做本地 rename）。
func (s *Service) UpdateFileMeta(path string, baseMetaGeneration int64, metaEnc, canonicalHash, deviceID string) (*MetaUpdateResult, error) {
	if !isHex32(path) || metaEnc == "" || !isHex64(canonicalHash) || baseMetaGeneration < 0 {
		return nil, ErrMetaRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 状态守卫（v0.12.1 / LS-121-S03）：只有仓库确实处在元数据迁移或
	// 元数据加密状态时，才允许写入 meta_enc / canonical HMAC / metaGeneration。
	// plain 状态下这些字段没有任何合法来源——放行等于允许用特制文件名污染
	// 元数据语义（例如给普通文件挂上伪造的 canonical 键去顶掉别人的路径）。
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState != db.MetaMigrating && rs.MetaState != db.MetaEncrypted {
		return nil, ErrEncryptionState
	}

	cur, err := db.GetFile(s.db, path)
	if err != nil {
		return nil, err
	}
	if cur == nil || cur.Deleted {
		return nil, ErrNotFound
	}
	if cur.MetaGeneration != baseMetaGeneration {
		return nil, ErrMetaCAS
	}
	// 新名字与其他现存文件同名 → 拒绝（HMAC 比较，不泄露路径）
	if other, err := db.FindCanonicalCollision(s.db, "h:"+canonicalHash, path); err != nil {
		return nil, err
	} else if other != "" {
		return nil, &PathCollisionError{Path: path, Existing: other}
	}

	now := time.Now().Unix()
	newGen := cur.MetaGeneration + 1

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	cur.MetaEnc = metaEnc
	cur.MetaGeneration = newGen
	cur.CanonicalKey = "h:" + canonicalHash
	cur.UpdatedAt = now
	if err := db.UpsertFile(tx, cur); err != nil {
		return nil, err
	}
	seq, err := db.InsertChangeMeta(tx, path, cur.Revision, "upsert", cur.ContentHash, now, newGen)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.log.Info("meta update", "fileId", cur.FileID, "metaGen", newGen, "device", deviceID)
	return &MetaUpdateResult{Path: path, Revision: cur.Revision, MetaGeneration: newGen, Sequence: seq}, nil
}

// MigrateFileMeta 迁移单个文件：真实路径行 → 伪名行（单事务，断点续传安全）。
func (s *Service) MigrateFileMeta(fromPath, metaEnc, canonicalHash, deviceID string) (*MoveResult, error) {
	if metaEnc == "" || !isHex64(canonicalHash) {
		return nil, ErrMetaRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState != db.MetaMigrating {
		return nil, ErrEncryptionState
	}

	from, err := db.GetFile(s.db, fromPath)
	if err != nil {
		return nil, err
	}
	if from == nil || from.Deleted {
		return nil, ErrNotFound
	}
	// 内容必须已是 LSE3（fileId-AAD）——否则搬到伪名路径后无法解密
	if _, isV3 := s.lse3GenerationFromBlob(from.ContentHash); !isV3 {
		return nil, ErrPlaintextRejected
	}

	pseudonym := from.FileID
	now := time.Now().Unix()

	// 幂等：已是伪名行 → 只补/更新元数据
	if fromPath == pseudonym {
		if from.MetaEnc == metaEnc {
			return &MoveResult{FromPath: fromPath, ToPath: pseudonym, Revision: from.Revision, Sequence: 0}, nil
		}
		tx, err := s.db.Begin()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback() //nolint:errcheck
		from.MetaEnc = metaEnc
		from.MetaGeneration = max(from.MetaGeneration, 1)
		from.CanonicalKey = "h:" + canonicalHash
		from.UpdatedAt = now
		if err := db.UpsertFile(tx, from); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &MoveResult{FromPath: fromPath, ToPath: pseudonym, Revision: from.Revision, Sequence: 0}, nil
	}

	// 伪名位置被占（不应发生：fileId 唯一）→ 拒绝
	if occupied, err := db.GetFile(s.db, pseudonym); err != nil {
		return nil, err
	} else if occupied != nil && !occupied.Deleted {
		return nil, &ConflictError{Path: pseudonym, Revision: occupied.Revision}
	}

	tombRev := from.Revision + 1
	tombID, err := db.NewFileID()
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// 1) 原真实路径 → tombstone（complete 时整体删除；迁移窗口内保留防复活）
	if err := db.UpsertFile(tx, &db.File{
		Path: fromPath, ContentHash: from.ContentHash, Size: from.Size, Mtime: from.Mtime,
		Revision: tombRev, Deleted: true, CreatedAt: from.CreatedAt, UpdatedAt: now,
		CanonicalKey: from.CanonicalKey, FileID: tombID,
	}); err != nil {
		return nil, err
	}
	if _, err := db.InsertChange(tx, fromPath, tombRev, "delete", "", now); err != nil {
		return nil, err
	}

	// 2) 伪名行：内容/身份原样继承 + 挂上加密元数据
	if err := db.UpsertFile(tx, &db.File{
		Path: pseudonym, ContentHash: from.ContentHash, Size: from.Size, Mtime: from.Mtime,
		Revision: 1, Deleted: false, CreatedAt: from.CreatedAt, UpdatedAt: now,
		CanonicalKey: "h:" + canonicalHash, FileID: from.FileID,
		MetaEnc: metaEnc, MetaGeneration: 1,
	}); err != nil {
		return nil, err
	}
	seq, err := db.InsertChangeMeta(tx, pseudonym, 1, "upsert", from.ContentHash, now, 1)
	if err != nil {
		return nil, err
	}
	// 3) 该文件的历史版本路径改写为伪名（LSE3 历史按 fileId 解密，不受影响；
	//    旧信封历史在 complete 时统一清除）
	if _, err := tx.Exec(`UPDATE file_versions SET path = ? WHERE path = ?`, pseudonym, fromPath); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.log.Info("meta migrate", "fileId", from.FileID, "device", deviceID)
	return &MoveResult{FromPath: fromPath, ToPath: pseudonym, Revision: 1, TombstoneRevision: tombRev, Sequence: seq}, nil
}

// BeginMetaMigration：plain → migrating（幂等）。前置：内容加密必须已是 encrypted。
func (s *Service) BeginMetaMigration() (*db.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.EncryptionState != db.EncryptionEncrypted {
		return nil, ErrEncryptionState // 先启用 E2EE 才谈得上元数据加密
	}
	switch rs.MetaState {
	case db.MetaMigrating:
		return rs, nil
	case db.MetaEncrypted:
		return nil, ErrEncryptionState
	}
	if err := db.SetMetaState(s.db, db.MetaMigrating); err != nil {
		return nil, err
	}
	return db.GetRepoState(s.db)
}

// CompleteMetaMigration：验证全部未删除文件均已伪名化（path==file_id 且带 meta），
// 然后执行明文路径抹除（单向点）：
//   - 清除旧信封（非 LSE3）历史版本（其 path 已改写但内容按路径 AAD 无法再解）
//   - 全量裁剪 changes 并把水位线推到 head（旧 changes 的明文路径消失，
//     所有客户端下轮 snapshot 对账，快照只含伪名+密文元数据）
//
// v0.12.1（LS-121-S02）：**不再删除 tombstone**。
//
// 旧实现用 `DELETE FROM files WHERE deleted = 1` 来抹掉 tombstone 行里的明文
// 路径，代价是把「删除事实」本身一起丢掉（INV-06）：一台离线很久的旧设备
// 重新上线后，会把本已删除的文件当成新文件重新建档复活。
//
// 「擦除明文」永远不是丢失删除屏障的理由。因此当仓库里还存在携带明文路径的
// tombstone 时，complete 直接拒绝并返回 ErrTombstonePlaintext——迁移停在
// migrating（可 abort 回退，已伪名化的行照常工作）。把 tombstone 转成不泄露
// 路径又能防复活的隐私 ledger 是 v0.13.0 / 协议 v6 的工作。
func (s *Service) CompleteMetaMigration() (*db.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState != db.MetaMigrating {
		return nil, ErrEncryptionState
	}
	files, err := db.ListFiles(s.db)
	if err != nil {
		return nil, err
	}
	for i := range files {
		f := &files[i]
		if f.Path != f.FileID || f.MetaEnc == "" {
			return nil, ErrMetaRequired
		}
		if _, isV3 := s.lse3GenerationFromBlob(f.ContentHash); !isV3 {
			return nil, ErrPlaintextRejected
		}
	}

	// 明文 tombstone 检查（LS-121-S02）：只要还有一行删除记录的 path 不是伪名，
	// 就无法在不丢删除屏障的前提下完成抹除 → 拒绝 complete
	var plainTombstones int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM files WHERE deleted = 1 AND path != file_id`).Scan(&plainTombstones); err != nil {
		return nil, err
	}
	if plainTombstones > 0 {
		s.log.Warn("meta complete refused: plaintext tombstones would have to be dropped",
			"tombstones", plainTombstones)
		return nil, ErrTombstonePlaintext
	}

	// 收集将被清除的旧信封历史的 blob（事务后 GC）
	rows, err := s.db.Query(
		`SELECT DISTINCT blob_id FROM file_versions WHERE COALESCE(blob_id, '') != ''`)
	if err != nil {
		return nil, err
	}
	var candidates []string
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return nil, err
		}
		if _, isV3 := s.lse3GenerationFromBlob(b); !isV3 {
			candidates = append(candidates, b)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// 注意：这里**不删除 tombstone**（LS-121-S02）。删除事实必须保留，
	// 否则旧设备重新上线会复活已删内容（INV-06）。
	// 旧信封历史（path AAD，改写路径后永远无法解密）→ 连元数据一起清除
	if _, err := tx.Exec(
		`DELETE FROM file_versions WHERE id IN (
			SELECT v.id FROM file_versions v WHERE COALESCE(v.blob_id, '') != '' AND v.blob_id IN (`+
			placeholders(len(candidates))+`)
		)`, toAny(candidates)...); err != nil {
		return nil, err
	}
	// 明文路径抹除：全量裁剪 changes + 水位线推到 head → 全体客户端 snapshot 对账
	if _, err := tx.Exec(`DELETE FROM changes`); err != nil {
		return nil, err
	}
	if err := db.SetMinRetainedSequence(tx, rs.HeadSequence); err != nil {
		return nil, err
	}
	if err := db.SetMetaState(tx, db.MetaEncrypted); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// 事务外 GC（锁内二次确认引用的既有安全语义）
	s.gcBlobs(candidates)

	s.log.Info("meta migration complete: plaintext paths erased",
		"files", len(files), "oldEnvelopeBlobs", len(candidates))
	return db.GetRepoState(s.db)
}

// AbortMetaMigration：migrating → plain。已迁移的伪名行保持原样（混合态可正常同步），
// 不做任何删除或改写。
func (s *Service) AbortMetaMigration() (*db.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState != db.MetaMigrating {
		return nil, ErrEncryptionState
	}
	if err := db.SetMetaState(s.db, db.MetaPlain); err != nil {
		return nil, err
	}
	return db.GetRepoState(s.db)
}

// isHex64 校验 32 字节 hex（canonical path HMAC）。
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func placeholders(n int) string {
	if n == 0 {
		return "''" // 空集合：IN ('') 永假
	}
	out := "?"
	for i := 1; i < n; i++ {
		out += ",?"
	}
	return out
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
