package sync

import (
	"errors"
	"strings"

	"github.com/KJoner/litesync-server/internal/db"
)

// 签名 checkpoint 的服务端职责（v0.15.0 / 计划书 §9）。
//
// 需要非常明确地划清界限：**服务器不是这套机制的权威**。它做三件事——
//
//	1. 存（只追加，不改不删）；
//	2. 转发（按客户端的游标给出链上的后续 checkpoint）；
//	3. 拒绝已撤销设备的发布（§9.2）。
//
// 它**不**做的事：验证签名、判断哪条链是「对的」、在分叉时做选择。
// 这三件事只要交给服务器，整套机制就退化成「相信服务器」——
// 而这正是本阶段要消除的前提。

var (
	// ErrCheckpointRevokedDevice：已撤销设备不得再发布 checkpoint（§9.2）
	ErrCheckpointRevokedDevice = errors.New("device is revoked and cannot publish checkpoints")
	// ErrCheckpointNoSigningKey：该设备还没登记签名公钥
	ErrCheckpointNoSigningKey = errors.New("device has no registered signing key")
	// ErrCheckpointEpochMismatch：checkpoint 的 repoEpoch 与当前仓库不符
	ErrCheckpointEpochMismatch = errors.New("checkpoint repo epoch mismatch")
	// ErrCheckpointInvalid：字段缺失或格式不合法
	ErrCheckpointInvalid = errors.New("invalid checkpoint")
)

// PublishCheckpointParams 是客户端发布 checkpoint 时提交的内容。
type PublishCheckpointParams struct {
	Hash         string
	RepoEpoch    string
	HeadSequence int64
	PreviousHash string
	DeviceID     string
	// Body 是客户端算出的 canonical 原文；服务器原样保存，不解析、不重排
	Body      string
	Signature string
}

// PublishCheckpoint 保存一个由设备签名的 checkpoint。
func (s *Service) PublishCheckpoint(p PublishCheckpointParams) error {
	if p.Hash == "" || p.Body == "" || p.Signature == "" || p.DeviceID == "" {
		return ErrCheckpointInvalid
	}
	if len(p.Body) > 8192 || len(p.Signature) > 512 || len(p.Hash) != 64 {
		return ErrCheckpointInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db, s.scope())
	if err != nil {
		return err
	}
	// epoch 不符 = 这个 checkpoint 描述的是灾备恢复之前的仓库。
	// 存下来只会污染当前 epoch 的链
	if p.RepoEpoch != rs.RepoEpoch {
		return ErrCheckpointEpochMismatch
	}

	// §9.2：撤销之后不得再发布。设备被撤销通常意味着它丢了或被攻陷，
	// 而它的签名私钥仍然是有效私钥——只靠客户端验签名是拦不住的，
	// 服务器这一层能减少这类 checkpoint 进入流通
	devices, err := db.ListDevices(s.db)
	if err != nil {
		return err
	}
	var signer *db.Device
	for i := range devices {
		if devices[i].DeviceID == p.DeviceID {
			signer = &devices[i]
			break
		}
	}
	if signer == nil {
		return ErrCheckpointNoSigningKey
	}
	if signer.Revoked {
		return ErrCheckpointRevokedDevice
	}
	if signer.SigningPublicKey == "" {
		return ErrCheckpointNoSigningKey
	}

	// 注意这里**不**校验「同一 head 上是否已有别的 checkpoint」：
	// 那种冲突正是分叉证据，必须原样保留下来让客户端看到（§9.4）。
	// 服务器悄悄拒掉第二份，等于替用户隐瞒了一次 equivocation。
	return db.InsertCheckpoint(s.db, &db.Checkpoint{
		Hash:            p.Hash,
		VaultID:         db.DefaultVaultID,
		RepoEpoch:       p.RepoEpoch,
		HeadSequence:    p.HeadSequence,
		PreviousHash:    p.PreviousHash,
		SigningDeviceID: p.DeviceID,
		Body:            p.Body,
		Signature:       p.Signature,
	})
}

// RegisterSigningKey 登记设备的 checkpoint 签名公钥（首次接入时）。
func (s *Service) RegisterSigningKey(deviceID, spkiB64 string) error {
	if deviceID == "" || spkiB64 == "" || len(spkiB64) > 512 || strings.ContainsAny(spkiB64, "\n\r") {
		return ErrCheckpointInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.SetDeviceSigningKey(s.db, deviceID, spkiB64)
}

// CheckpointBundle 是客户端拉取 checkpoint 时拿到的一组数据。
type CheckpointBundle struct {
	RepoEpoch string
	// Checkpoints：游标之后的链（升序）
	Checkpoints []db.Checkpoint
	// Conflicting：与最新 head 同位置的其他 checkpoint。
	// 非空即分叉证据——客户端据此停机并展示（§9.4）
	Conflicting []db.Checkpoint
	// SigningKeys：deviceId → base64 SPKI 公钥。
	// 客户端**不能**只凭这里的公钥就相信一个签名者：新设备的信任集合
	// 必须经配对建立（§9.3）。这里给出的是「服务器声称的」，
	// 只用于识别，不用于授信
	SigningKeys map[string]string
	// RevokedDevices：已撤销设备清单（同样只是服务器的说法，供参考）
	RevokedDevices []string
}

// Checkpoints 返回给定游标之后的 checkpoint 链与分叉证据。
func (s *Service) Checkpoints(sinceSequence int64, limit int) (*CheckpointBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db, s.scope())
	if err != nil {
		return nil, err
	}
	list, err := db.CheckpointsSince(s.db, db.DefaultVaultID, rs.RepoEpoch, sinceSequence, limit)
	if err != nil {
		return nil, err
	}
	out := &CheckpointBundle{RepoEpoch: rs.RepoEpoch, Checkpoints: list, SigningKeys: map[string]string{}}

	// 同一 head 上的多份 checkpoint = equivocation 证据，原样带上
	latest, err := db.LatestCheckpoint(s.db, db.DefaultVaultID, rs.RepoEpoch)
	if err != nil {
		return nil, err
	}
	if latest != nil {
		at, aerr := db.CheckpointsAtSequence(s.db, db.DefaultVaultID, rs.RepoEpoch, latest.HeadSequence)
		if aerr != nil {
			return nil, aerr
		}
		if len(at) > 1 {
			out.Conflicting = at
		}
	}

	devices, err := db.ListDevices(s.db)
	if err != nil {
		return nil, err
	}
	for i := range devices {
		d := &devices[i]
		if d.SigningPublicKey != "" {
			out.SigningKeys[d.DeviceID] = d.SigningPublicKey
		}
		if d.Revoked {
			out.RevokedDevices = append(out.RevokedDevices, d.DeviceID)
		}
	}
	return out, nil
}
