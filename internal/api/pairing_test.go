package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func pairingReq(t *testing.T, e *testEnv, method, path, bearer, body string) (*http.Response, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	json.NewDecoder(resp.Body).Decode(&out) //nolint:errcheck
	return resp, out
}

func TestPairingLifecycle(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 创建需要 Token
	resp, _ := pairingReq(t, e, "POST", "/api/v1/pairing", "", `{"ciphertext":"AAAA"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("create without token: %d", resp.StatusCode)
	}
	resp, body := pairingReq(t, e, "POST", "/api/v1/pairing", testToken, `{"ciphertext":"ZW5jcnlwdGVk","ttlSeconds":300}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %v", resp.StatusCode, body)
	}
	id, _ := body["id"].(string)
	if len(id) != 32 {
		t.Fatalf("bad pairing id: %q", id)
	}

	// 消费是公开接口（新设备还没有 Token），只能成功一次
	resp, body = pairingReq(t, e, "POST", "/pair/"+id+"/consume", "", "")
	if resp.StatusCode != http.StatusOK || body["ciphertext"] != "ZW5jcnlwdGVk" {
		t.Fatalf("consume: %d %v", resp.StatusCode, body)
	}
	resp, _ = pairingReq(t, e, "POST", "/pair/"+id+"/consume", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second consume must 404, got %d", resp.StatusCode)
	}
}

func TestPairingRevoke(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	_, body := pairingReq(t, e, "POST", "/api/v1/pairing", testToken, `{"ciphertext":"c2VjcmV0"}`)
	id := body["id"].(string)

	// 撤销需要 Token
	resp, _ := pairingReq(t, e, "DELETE", "/api/v1/pairing/"+id, "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("delete without token: %d", resp.StatusCode)
	}
	resp, _ = pairingReq(t, e, "DELETE", "/api/v1/pairing/"+id, testToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	resp, _ = pairingReq(t, e, "POST", "/pair/"+id+"/consume", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("consume after revoke must 404, got %d", resp.StatusCode)
	}
}

func TestPairingRejectsOversizedAndEmpty(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, _ := pairingReq(t, e, "POST", "/api/v1/pairing", testToken, `{"ciphertext":""}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty ciphertext: %d", resp.StatusCode)
	}
	big := strings.Repeat("A", 9<<10)
	resp, _ = pairingReq(t, e, "POST", "/api/v1/pairing", testToken, `{"ciphertext":"`+big+`"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized ciphertext: %d", resp.StatusCode)
	}
}

func TestInfoVaultIDStable(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	get := func() string {
		req, _ := http.NewRequest("GET", e.ts.URL+"/api/v1/info", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct {
			VaultID string `json:"vaultId"`
		}
		json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
		return body.VaultID
	}
	id1 := get()
	if len(id1) != 32 {
		t.Fatalf("vaultId should be 32 hex chars, got %q", id1)
	}
	if id2 := get(); id2 != id1 {
		t.Fatalf("vaultId must be stable: %q vs %q", id1, id2)
	}
}

func TestPairLandingPublic(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, err := http.Get(e.ts.URL + "/p/" + strings.Repeat("ab", 16))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body) //nolint:errcheck
	if resp.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte("pair.js")) {
		t.Fatalf("landing page: %d %.80s", resp.StatusCode, raw)
	}
}
