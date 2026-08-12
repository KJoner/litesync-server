package sync

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
)

// access token 里与时间有关的性质（v0.16.0 / §10.5）。
//
// 这些放在包内测试，是因为「造一张已经过期的票」需要用服务端签名密钥——
// 而那把密钥不该为了测试而暴露出去。等五分钟不是测试该做的事。

func TestAccessTokenExpiryIsEnforced(t *testing.T) {
	s, deviceID := newTokenEnv(t)

	// 用真实的签名路径造一张一分钟前就过期的票
	expired := s.mintForTest(t, &AccessClaims{
		DeviceID: deviceID, VaultID: "default", Scopes: ScopeSync,
		IssuedAt: time.Now().Add(-2 * time.Minute).Unix(),
		// 过期
		ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	})
	if _, err := s.VerifyAccessToken(expired); err != ErrAccessTokenExpired {
		t.Fatalf("过期票必须被拒，得到 %v", err)
	}

	// 同样的签名路径、只是没过期 → 必须通过。
	// 没有这条对照，上面那条可能只是「签名根本不对」而不是「过期被发现了」
	fresh := s.mintForTest(t, &AccessClaims{
		DeviceID: deviceID, VaultID: "default", Scopes: ScopeSync,
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if _, err := s.VerifyAccessToken(fresh); err != nil {
		t.Fatalf("未过期的票应当通过，得到 %v", err)
	}
}

// 签发时的 TTL 上限：能要到几天的话，这就是第二种长期凭据。
func TestAccessTokenTTLIsCapped(t *testing.T) {
	s, deviceID := newTokenEnv(t)
	_, claims, err := s.IssueAccessToken(deviceID, nil, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := claims.ExpiresAt - claims.IssuedAt; got > int64(accessTokenMaxTTL.Seconds()) {
		t.Fatalf("TTL 应当被截到 %v，得到 %d 秒", accessTokenMaxTTL, got)
	}
}

// 一个 Vault 的签名密钥换不到另一个的票：密钥必须真的参与签名。
func TestAccessTokenSignatureDependsOnServerSecret(t *testing.T) {
	s1, dev1 := newTokenEnv(t)
	s2, _ := newTokenEnv(t)

	token, _, err := s1.IssueAccessToken(dev1, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.VerifyAccessToken(token); err != ErrAccessTokenInvalid {
		t.Fatalf("另一台服务器签发的票必须被拒，得到 %v", err)
	}
}

// mintForTest 用真实的签名路径造一张任意 claims 的票。
func (s *Service) mintForTest(t *testing.T, c *AccessClaims) string {
	t.Helper()
	secret, err := s.tokenSigningSecret()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return accessTokenPrefix + "." + body + "." + signAccessToken(secret, body)
}

// newTokenEnv 造一个带一台已注册设备的服务。
func newTokenEnv(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, _ := storage.New(filepath.Join(dir, "vault"))
	blobs, _ := storage.NewBlobStore(filepath.Join(dir, "blobs"))
	shares, _ := storage.NewShareStore(filepath.Join(dir, "shares"))
	s := New(database, store, blobs, shares, Options{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	cred, err := s.CreateDevice("test-device")
	if err != nil {
		t.Fatal(err)
	}
	return s, cred.DeviceID
}
