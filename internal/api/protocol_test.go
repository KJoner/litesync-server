package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestInfoProtocolVersion：/api/v1/info 必须携带协议版本区间（v7 起插件与服务器
// 独立发版，客户端据此判定兼容性，而不是比对版本号）。
func TestInfoProtocolVersion(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/v1/info", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Version            string `json:"version"`
		ProtocolVersion    int    `json:"protocolVersion"`
		MinProtocolVersion int    `json:"minProtocolVersion"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ProtocolVersion < 1 || body.MinProtocolVersion < 1 {
		t.Fatalf("info must report protocol range, got %+v", body)
	}
	if body.MinProtocolVersion > body.ProtocolVersion {
		t.Fatalf("min > current: %+v", body)
	}
}
