package sync

// 跨产品撤销事件的编码与签名（ADR-019 §2.4「签名与编码细则」，2026-11-21 与 Nexus 定稿）。
// 固定测试向量与 Nexus 的 peer-revocation.test.ts 是同一组（用 `openssl dgst -sha256 -hmac` 独立算出）：
// 两边各自断言与它相等，就保证了两个实现逐字节一致。覆盖 INV-12（事件只按 (issuer, subject) 定位）。

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const (
	vectorSecret    = "0123456789abcdef0123456789abcdef"
	vectorTimestamp = "1795244400"
	vectorBody      = `{"v":1,"eventId":"00112233445566778899aabbccddeeff","issuer":"https://accounts.example.com/realms/accounts","subject":"6d767bc8-2754-47d1-a6b8-f58b6587ec7b","scope":"all-products-all-devices","reason":"user-request","origin":"litesync","occurredAt":"2026-11-21T07:00:00Z"}`
	vectorSignature = "v1=2a1be7920f41d24348685b4e28ca00c26edf5da13a2440e5d8030d8f85d2417c"
)

func TestPeerSignatureMatchesTheSharedVector(t *testing.T) {
	if got := SignPeerRevocation(vectorSecret, vectorTimestamp, []byte(vectorBody)); got != vectorSignature {
		t.Fatalf("signature = %s\nwant      %s", got, vectorSignature)
	}
}

// 发送端序列化出来的请求体必须与向量**逐字节**相同：字段顺序 v,eventId,issuer,subject,scope,reason,
// origin,occurredAt；occurredAt 秒精度、UTC、以 Z 结尾（输入带纳秒、带时区也一样）。
func TestPeerPayloadIsByteExact(t *testing.T) {
	at := time.Date(2026, 11, 21, 15, 0, 0, 987654321, time.FixedZone("UTC+8", 8*3600)) // = 07:00:00.987Z
	got, err := peerPayload("00112233445566778899aabbccddeeff", "https://accounts.example.com/realms/accounts",
		"6d767bc8-2754-47d1-a6b8-f58b6587ec7b", "user-request", at)
	if err != nil {
		t.Fatal(err)
	}
	if got != vectorBody {
		t.Fatalf("payload =\n%s\nwant\n%s", got, vectorBody)
	}
	if SignPeerRevocation(vectorSecret, vectorTimestamp, []byte(got)) != vectorSignature {
		t.Fatal("the serialized payload does not reproduce the shared signature")
	}
}

func peerTestService() *Service {
	s := &Service{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.SetPeerRevocation(PeerRevocationConfig{URL: "http://peer.invalid", Secret: vectorSecret})
	return s
}

// 接收端：先常数时间验签，再查 ±300 秒时间窗；签名大小写不敏感；头格式不对一律 401（ErrPeerSignature）。
func TestVerifyPeerRevocationVectorWindowAndFormat(t *testing.T) {
	s := peerTestService()
	base := time.Unix(1795244400, 0)
	for _, skew := range []time.Duration{0, 300 * time.Second, -300 * time.Second} {
		if err := s.VerifyPeerRevocation(vectorTimestamp, vectorSignature, []byte(vectorBody), base.Add(skew)); err != nil {
			t.Fatalf("vector at skew %v = %v", skew, err)
		}
	}
	for _, skew := range []time.Duration{301 * time.Second, -301 * time.Second} {
		if err := s.VerifyPeerRevocation(vectorTimestamp, vectorSignature, []byte(vectorBody), base.Add(skew)); !errors.Is(err, ErrPeerSignature) {
			t.Fatalf("vector at skew %v = %v, want ErrPeerSignature", skew, err)
		}
	}
	upper := "v1=" + strings.ToUpper(strings.TrimPrefix(vectorSignature, "v1="))
	if err := s.VerifyPeerRevocation(vectorTimestamp, upper, []byte(vectorBody), base); err != nil {
		t.Fatalf("upper-case hex signature = %v", err)
	}
	for name, tc := range map[string]struct{ ts, sig, body string }{
		"body changed":      {vectorTimestamp, vectorSignature, strings.Replace(vectorBody, "user-request", "user-requesT", 1)},
		"timestamp changed": {"1795244401", vectorSignature, vectorBody},
		"signed ts +1":      {"+1795244400", vectorSignature, vectorBody},
		"no v1 prefix":      {vectorTimestamp, strings.TrimPrefix(vectorSignature, "v1="), vectorBody},
		"short signature":   {vectorTimestamp, vectorSignature[:40], vectorBody},
		"empty headers":     {"", "", vectorBody},
		"non-numeric stamp": {"17952444OO", vectorSignature, vectorBody},
		"extra signature":   {vectorTimestamp, vectorSignature + ",v1=00", vectorBody},
	} {
		if err := s.VerifyPeerRevocation(tc.ts, tc.sig, []byte(tc.body), base); !errors.Is(err, ErrPeerSignature) {
			t.Fatalf("%s = %v, want ErrPeerSignature", name, err)
		}
	}
	if err := (&Service{}).VerifyPeerRevocation(vectorTimestamp, vectorSignature, []byte(vectorBody), base); !errors.Is(err, ErrPeerNotEnabled) {
		t.Fatalf("unconfigured receiver = %v", err)
	}
}

// 格式校验（签名通过之后）：与 Nexus 同一套规则。
func TestParsePeerEventRules(t *testing.T) {
	// 向量本身是 LiteSync 发出的（origin=litesync）：LiteSync 收到它说明配置成了环，必须拒绝
	if _, err := ParsePeerEvent([]byte(vectorBody)); !errors.Is(err, ErrPeerMalformed) {
		t.Fatalf("an event with origin=litesync arriving at litesync = %v, want ErrPeerMalformed", err)
	}
	fromNexus := strings.Replace(vectorBody, `"origin":"litesync"`, `"origin":"nexus"`, 1)
	ev, err := ParsePeerEvent([]byte(fromNexus))
	if err != nil || ev.Subject != "6d767bc8-2754-47d1-a6b8-f58b6587ec7b" || ev.Origin != "nexus" {
		t.Fatalf("nexus event = %+v %v", ev, err)
	}
	upperID := strings.Replace(fromNexus, "00112233445566778899aabbccddeeff", "00112233445566778899AABBCCDDEEFF", 1)
	if ev, err := ParsePeerEvent([]byte(upperID)); err != nil || ev.EventID != "00112233445566778899aabbccddeeff" {
		t.Fatalf("upper-case eventId must be accepted and normalized: %+v %v", ev, err)
	}
	millis := strings.Replace(fromNexus, "07:00:00Z", "07:00:00.123Z", 1)
	if _, err := ParsePeerEvent([]byte(millis)); err != nil {
		t.Fatalf("occurredAt with milliseconds = %v", err)
	}
	for name, mutate := range map[string][2]string{
		"version 2":     {`"v":1`, `"v":2`},
		"short id":      {`"eventId":"00112233445566778899aabbccddeeff"`, `"eventId":"0011"`},
		"other scope":   {`"all-products-all-devices"`, `"product-devices"`},
		"empty reason":  {`"reason":"user-request"`, `"reason":""`},
		"empty subject": {`"subject":"6d767bc8-2754-47d1-a6b8-f58b6587ec7b"`, `"subject":""`},
		"bad time":      {`"2026-11-21T07:00:00Z"`, `"yesterday"`},
	} {
		if _, err := ParsePeerEvent([]byte(strings.Replace(fromNexus, mutate[0], mutate[1], 1))); !errors.Is(err, ErrPeerMalformed) {
			t.Fatalf("%s = %v, want ErrPeerMalformed", name, err)
		}
	}
	long := strings.Replace(fromNexus, `"reason":"user-request"`, `"reason":"`+strings.Repeat("r", 65)+`"`, 1)
	if _, err := ParsePeerEvent([]byte(long)); !errors.Is(err, ErrPeerMalformed) {
		t.Fatalf("reason over 64 bytes = %v", err)
	}
}
