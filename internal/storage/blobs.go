package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/KJoner/litesync-server/internal/failpoint"
)

// syncDir 在 rename 后 fsync 父目录，保证目录项本身落盘（掉电后 rename 不丢失）。
// Windows 不支持目录句柄 fsync，跳过；其余平台尽力而为。
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if f, err := os.Open(dir); err == nil {
		f.Sync() //nolint:errcheck
		f.Close()
	}
}

var ErrInvalidBlobID = errors.New("invalid blob id")

// BlobStore 是内容寻址的不可变 blob 存储：/blobs/<hash[:2]>/<hash>。
// 相同内容只保存一份；写入后不再修改。
type BlobStore struct {
	root string
}

func NewBlobStore(root string) (*BlobStore, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &BlobStore{root: abs}, nil
}

func (b *BlobStore) path(hash string) (string, error) {
	if len(hash) != 64 {
		return "", ErrInvalidBlobID
	}
	for _, r := range hash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", ErrInvalidBlobID
		}
	}
	return filepath.Join(b.root, hash[:2], hash), nil
}

func (b *BlobStore) Has(hash string) bool {
	p, err := b.path(hash)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// PutReader 将内容写入 blob（临时文件 → 校验 hash → 原子改名）。
// blob 已存在时直接成功（内容寻址天然去重）。
func (b *BlobStore) PutReader(hash string, r io.Reader) error {
	p, err := b.path(hash)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), tmpPrefix+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != hash {
		os.Remove(tmp)
		return ErrHashMismatch
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(p))
	return nil
}

// IngestVerify 把内容流写入临时文件并计算 SHA-256（不持有任何业务锁，供上传路径使用）。
// 调用方随后在锁内 Commit（原子入库）或 Discard。
func (b *BlobStore) IngestVerify(r io.Reader) (tmpPath, hashHex string, size int64, err error) {
	f, err := os.CreateTemp(b.root, tmpPrefix+"*")
	if err != nil {
		return "", "", 0, err
	}
	tmpPath = f.Name()
	h := sha256.New()
	size, err = io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		f.Close()
		os.Remove(tmpPath)
		return "", "", 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return "", "", 0, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return "", "", 0, err
	}
	// §8.1 注入点：临时文件已 fsync、尚未入库。此刻崩溃只应留下一个孤儿临时文件，
	// 绝不能让任何已确认的 HEAD 指向它
	if err := failpoint.Eval(failpoint.BlobAfterTempFsync); err != nil {
		os.Remove(tmpPath)
		return "", "", 0, err
	}
	return tmpPath, hex.EncodeToString(h.Sum(nil)), size, nil
}

// CommitResult 描述一次 Commit 到底做了什么（v0.13.3 / 计划书 §7.1）。
// 调用方据此记录完整性事件——「悄悄修好」和「本来就没坏」必须区分得开。
type CommitResult struct {
	// Deduped：命中了内容一致的现有 blob，临时文件已丢弃
	Deduped bool
	// Repaired：现有 blob 已损坏，被隔离后用本次校验过的副本替换
	Repaired bool
	// QuarantinePath：Repaired 时坏副本的存放位置（供人工取证）
	QuarantinePath string
	// Reason：Repaired 的判定依据（size-mismatch / hash-mismatch / unreadable）
	Reason string
}

// Commit 把 IngestVerify 的临时文件原子改名为 blob（v0.13.3 / §7.1）。
//
// 去重命中时**不能**因为「同名且同大小」就丢弃这次正确的重传：
//
//  1. 先比大小（廉价，能抓到截断）；
//  2. strict 模式再算一遍现有 blob 的完整 hash（抓位腐坏）；
//  3. 判定损坏 → 把坏副本移进 quarantine（不是删除：那可能是取证的唯一线索）；
//  4. 用刚刚校验过 hash 的临时文件原子替换；
//  5. 返回 Repaired，调用方记完整性事件并重新检查所有引用。
//
// strict 模式对每次去重命中都要全量读一遍 blob，大文件上传会明显变慢；
// 因此它由配置开关控制，而不是默认全开。
func (b *BlobStore) Commit(tmpPath, hash string, strict bool) (CommitResult, error) {
	return b.CommitAs(tmpPath, hash, hash, strict)
}

// CommitAs 把临时文件落库到 blobID 这个名字下，用 contentHash 做完整性校验。
//
// v0.16.0 起两者不再相同：blobID = HMAC(vaultSecret, contentHash)（§10.3），
// 因此「文件叫什么」和「内容应该哈希成什么」必须分开传——
// 用文件名当期望哈希的老写法在域化之后会把每个 blob 都判成损坏。
func (b *BlobStore) CommitAs(tmpPath, blobID, contentHash string, strict bool) (CommitResult, error) {
	var res CommitResult
	p, err := b.path(blobID)
	if err != nil {
		os.Remove(tmpPath)
		return res, err
	}
	if cur, err := os.Stat(p); err == nil {
		tmpInfo, terr := os.Stat(tmpPath)
		switch {
		case terr != nil:
			// 连自己刚写的临时文件都读不到 → 别动现有 blob
			return res, terr
		case cur.Size() != tmpInfo.Size():
			res.Reason = "size-mismatch"
		case strict:
			ok, verr := b.VerifyContent(blobID, contentHash)
			if verr != nil {
				res.Reason = "unreadable"
			} else if !ok {
				res.Reason = "hash-mismatch"
			}
		}
		if res.Reason == "" {
			os.Remove(tmpPath)
			res.Deduped = true
			return res, nil
		}
		// 现有 blob 有问题 → 先隔离再替换
		if q, qerr := b.quarantine(blobID); qerr == nil {
			res.QuarantinePath = q
		}
		res.Repaired = true
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		os.Remove(tmpPath)
		return res, err
	}
	// §8.1 注入点：rename 之前。此刻崩溃 → blob 不在库里，上传必须整体失败并可重试
	if err := failpoint.Eval(failpoint.BlobBeforeRename); err != nil {
		os.Remove(tmpPath)
		return res, err
	}
	if err := os.Rename(tmpPath, p); err != nil {
		// Windows 的 rename 不能覆盖已存在文件（损坏修复路径）：先移除再试一次
		if os.Remove(p) == nil {
			if err2 := os.Rename(tmpPath, p); err2 == nil {
				syncDir(filepath.Dir(p))
				return res, nil
			}
		}
		os.Remove(tmpPath)
		return res, err
	}
	syncDir(filepath.Dir(p))
	// §8.1 注入点：blob 已经在库里，但数据库事务还没提交。
	// 此刻崩溃留下的是一个「无引用的 blob」——GC 会回收它，不会有任何数据损坏
	if err := failpoint.Eval(failpoint.BlobAfterRename); err != nil {
		return res, err
	}
	return res, nil
}

// QuarantineDir 是隔离区的目录名。它以 "_" 开头，因此 Walk 的
// 「文件名必须是 64 位十六进制」规则天然不会把隔离副本当成正常 blob。
const QuarantineDir = "_quarantine"

// quarantine 把一个已判定损坏的 blob 移进隔离区，返回新位置。
//
// 为什么不直接删：损坏的字节往往是查清「谁写坏的、什么时候坏的」的唯一线索。
// 隔离区有独立的清理策略（§7.3），不参与普通 GC。
func (b *BlobStore) quarantine(hash string) (string, error) {
	src, err := b.path(hash)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(b.root, QuarantineDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// 同一个 hash 可能被隔离多次；用递增序号避免互相覆盖
	for i := 0; ; i++ {
		dst := filepath.Join(dir, hash)
		if i > 0 {
			dst = filepath.Join(dir, hash+"."+strconv.Itoa(i))
		}
		if _, err := os.Stat(dst); err == nil {
			if i > 64 {
				return "", errors.New("quarantine slots exhausted")
			}
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			return "", err
		}
		syncDir(dir)
		return dst, nil
	}
}

// QuarantineEntry 是隔离区里的一份坏副本。
type QuarantineEntry struct {
	Path    string
	Hash    string
	Size    int64
	ModTime int64
}

// ListQuarantine 列出隔离区内容（运维接口与独立清理策略用）。
func (b *BlobStore) ListQuarantine() ([]QuarantineEntry, error) {
	dir := filepath.Join(b.root, QuarantineDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]QuarantineEntry, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		name := e.Name()
		hash := name
		if i := strings.IndexByte(name, '.'); i > 0 {
			hash = name[:i]
		}
		out = append(out, QuarantineEntry{
			Path:    filepath.Join(dir, name),
			Hash:    hash,
			Size:    info.Size(),
			ModTime: info.ModTime().Unix(),
		})
	}
	return out, nil
}

// PurgeQuarantine 删除隔离区中早于 before 的副本，返回删除数量。
func (b *BlobStore) PurgeQuarantine(before int64) (int, error) {
	ents, err := b.ListQuarantine()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		if e.ModTime >= before {
			continue
		}
		if err := os.Remove(e.Path); err == nil {
			n++
		}
	}
	return n, nil
}

// Discard 丢弃临时文件。
func (b *BlobStore) Discard(tmpPath string) {
	if tmpPath != "" {
		os.Remove(tmpPath)
	}
}

// Walk 遍历所有 blob（孤儿 GC 用），回调收到 hash 与文件信息。
//
// 隔离区被整个跳过（v0.13.3 / §7.3）：那里面的文件名与正常 blob 完全一样，
// 不跳过的话孤儿 GC 会把取证材料当成普通 blob 处理——而隔离区按定义就是
// 「有独立清理策略、不参与普通 GC」的地方。
func (b *BlobStore) Walk(fn func(hash string, info os.FileInfo) error) error {
	quarantine := filepath.Join(b.root, QuarantineDir)
	return filepath.WalkDir(b.root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // 尽力而为
		}
		if d.IsDir() {
			if p == quarantine {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if len(name) != 64 || strings.HasPrefix(name, tmpPrefix) {
			return nil
		}
		if _, perr := b.path(name); perr != nil {
			return nil // 非法命名，跳过
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil //nolint:nilerr
		}
		return fn(name, info)
	})
}

// StatSize 返回 blob 的磁盘尺寸；不存在或非法 id 返回 (0, false)。
func (b *BlobStore) StatSize(hash string) (int64, bool) {
	p, err := b.path(hash)
	if err != nil {
		return 0, false
	}
	info, err := os.Stat(p)
	if err != nil {
		return 0, false
	}
	return info.Size(), true
}

// VerifyHash 全量读取 blob 并校验内容 SHA-256 与文件名一致。
// 仅适用于未域化的 blob（blobID == contentHash）；scrub 请用 VerifyContent。
func (b *BlobStore) VerifyHash(hash string) (bool, error) {
	return b.VerifyContent(hash, hash)
}

// VerifyContent 全量读取 blobID 指向的文件，校验其内容哈希等于 contentHash（scrub 用）。
//
// 域化之后文件名不再是内容哈希，期望值必须由调用方从数据库带过来——
// 否则「校验」就退化成拿文件名和文件名比，永远为真。
func (b *BlobStore) VerifyContent(blobID, contentHash string) (bool, error) {
	f, err := b.Open(blobID)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == contentHash, nil
}

func (b *BlobStore) Open(hash string) (*os.File, error) {
	p, err := b.path(hash)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// Remove 删除 blob（不存在视为成功），并尽力清理空的分片目录。
func (b *BlobStore) Remove(hash string) error {
	p, err := b.path(hash)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	os.Remove(filepath.Dir(p)) // 目录非空时失败，忽略
	return nil
}
