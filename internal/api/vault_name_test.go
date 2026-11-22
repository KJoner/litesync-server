package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// 仓库名 1–64 个字符按 Unicode 码点计数（与网页的校验、报错文案同一口径）。
// 以前三个入口都按字节判断：22 个以上的汉字被拒，报错却写「1–64 个字符」（UI v2 实测发现，基线即有）。
func TestVaultNameLengthCountsCharacters(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	create := func(name string) (int, map[string]any) {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"name": name})
		resp, body := vaultReq(t, e, http.MethodPost, "/api/v1/vaults", testToken, "", payload)
		return resp.StatusCode, body
	}

	han30 := strings.Repeat("笔", 30) // 90 字节：以前会被拒
	code, body := create(han30)
	if code != http.StatusOK {
		t.Fatalf("30 个汉字的仓库名 = %d %v，应当可以创建", code, body)
	}
	id, _ := body["id"].(string)

	if code, body := create(strings.Repeat("记", 64)); code != http.StatusOK {
		t.Fatalf("正好 64 个汉字 = %d %v，应当可以创建", code, body)
	}
	if code, _ := create(strings.Repeat("记", 65)); code != http.StatusBadRequest {
		t.Fatalf("65 个汉字 = %d，应当 400", code)
	}
	if code, _ := create("   "); code != http.StatusBadRequest {
		t.Fatalf("空白仓库名 = %d，应当 400", code)
	}

	// 重命名走同一个规则
	rename, _ := json.Marshal(map[string]any{"name": strings.Repeat("改", 40)})
	if resp, body := vaultReq(t, e, http.MethodPatch, "/api/v1/vaults/"+id, testToken, "", rename); resp.StatusCode != http.StatusOK {
		t.Fatalf("重命名为 40 个汉字 = %d %v", resp.StatusCode, body)
	}
	tooLong, _ := json.Marshal(map[string]any{"name": strings.Repeat("改", 65)})
	if resp, _ := vaultReq(t, e, http.MethodPatch, "/api/v1/vaults/"+id, testToken, "", tooLong); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("重命名为 65 个汉字 = %d，应当 400", resp.StatusCode)
	}
}

// v2 建库（网页「新建仓库」走的入口）同样按字符计数。
func TestVaultNameLengthV2(t *testing.T) {
	e := newPublicTestEnv(t)
	alice, _, _ := registerUser(t, e, adminCreateInvite(t, e), "alice")
	r, b := e.call(t, http.MethodPost, "/api/v2/vaults", alice, "", map[string]any{"name": strings.Repeat("长", 40), "clientRequestId": "req_long_chinese_name_01"})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("v2 建库 40 个汉字 = %d %v，应当可以创建", r.StatusCode, b)
	}
	r, _ = e.call(t, http.MethodPost, "/api/v2/vaults", alice, "", map[string]any{"name": strings.Repeat("长", 65), "clientRequestId": "req_long_chinese_name_02"})
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("v2 建库 65 个汉字 = %d，应当 400", r.StatusCode)
	}
}
