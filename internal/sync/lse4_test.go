package sync

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// LSE4 信封的服务端识别（v0.17 / 计划书 §11.1）。
//
// 服务器不解密，但它必须能从信封头读出 keyEpoch 与 generation——
// 抗回退重放（INV-08）全靠这两个值。只认 LSE3 的话，填充过的对象
// 在服务器眼里 generation 恒为 0，世代校验会**静默**失效。

func lse4Envelope(flags byte, keyEpoch uint32, generation uint64) []byte {
	buf := make([]byte, 0, 17)
	buf = append(buf, lse4Magic...)
	buf = append(buf, flags)
	buf = binary.BigEndian.AppendUint32(buf, keyEpoch)
	buf = binary.BigEndian.AppendUint64(buf, generation)
	return buf
}

func lse3Envelope(keyEpoch uint32, generation uint64) []byte {
	buf := make([]byte, 0, 16)
	buf = append(buf, lse3Magic...)
	buf = binary.BigEndian.AppendUint32(buf, keyEpoch)
	buf = binary.BigEndian.AppendUint64(buf, generation)
	return buf
}

func TestEnvelopeVersionRecognizesLSE4(t *testing.T) {
	cases := map[string]struct {
		head []byte
		want int64
	}{
		"LSE4": {lse4Magic, 4},
		"LSE3": {lse3Magic, 3},
		"LSE2": {lse2Magic, 2},
		"LSE1": {lse1Magic, 1},
		"明文":   {[]byte("abcd"), 0},
	}
	for name, c := range cases {
		if got := envelopeVersion(c.head); got != c.want {
			t.Errorf("%s: envelopeVersion = %d, want %d", name, got, c.want)
		}
	}
}

// LSE4 的版本号大于现有下限 3，因此它**不需要迁移**就能被接受。
// 这条测试钉住这个性质：改动下限逻辑而忘了 LSE4 会让新写入被整体拒绝。
func TestLSE4SatisfiesExistingEnvelopeFloor(t *testing.T) {
	const floor = 3
	if envelopeVersion(lse4Magic) < floor {
		t.Fatal("LSE4 必须满足现有的信封下限，否则开启填充等于让所有上传被拒")
	}
}

func TestParseHeaderReadsBothLSE3AndLSE4(t *testing.T) {
	t.Run("LSE3", func(t *testing.T) {
		h, ok := parseLse3Header(bytes.NewReader(lse3Envelope(7, 42)))
		if !ok || h.keyEpoch != 7 || h.generation != 42 || h.version != 3 {
			t.Fatalf("LSE3 头解析错误：%+v ok=%v", h, ok)
		}
	})
	t.Run("LSE4", func(t *testing.T) {
		h, ok := parseLse3Header(bytes.NewReader(lse4Envelope(0x01, 9, 1234)))
		if !ok {
			t.Fatal("LSE4 头必须能解析——否则抗回退校验会静默失效")
		}
		if h.keyEpoch != 9 || h.generation != 1234 {
			t.Fatalf("LSE4 头字段错位：keyEpoch=%d generation=%d", h.keyEpoch, h.generation)
		}
		if h.flags != 0x01 || h.version != 4 {
			t.Fatalf("LSE4 flags/version 错误：%+v", h)
		}
	})
	t.Run("截断的 LSE4", func(t *testing.T) {
		short := lse4Envelope(0, 1, 1)[:16] // 少一个字节
		if _, ok := parseLse3Header(bytes.NewReader(short)); ok {
			t.Fatal("截断的 LSE4 头必须被拒——半个 generation 比没有更危险")
		}
	})
	t.Run("非信封", func(t *testing.T) {
		if _, ok := parseLse3Header(bytes.NewReader([]byte("plain text content here"))); ok {
			t.Fatal("明文不该被当成信封")
		}
	})
}
