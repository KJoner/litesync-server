package api

import (
	"testing"
	"time"
)

// 令牌桶按经过时间补充；上传并发槽在释放后可复用、重复释放无副作用；关闭时一律放行（需求 §12）。
func TestIdentityLimiterRefillAndUploadSlots(t *testing.T) {
	now := time.Unix(1_795_132_800, 0)
	l := newIdentityLimiter(120, 2) // 每秒 2 个，突发 60
	l.now = func() time.Time { return now }
	for i := 0; i < 60; i++ {
		if ok, _ := l.allow("u:a"); !ok {
			t.Fatalf("request %d within burst rejected", i)
		}
	}
	ok, wait := l.allow("u:a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("over burst: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.allow("u:b"); !ok {
		t.Fatal("another identity has its own bucket")
	}
	now = now.Add(time.Second) // 补充 2 个
	for i := 0; i < 2; i++ {
		if ok, _ := l.allow("u:a"); !ok {
			t.Fatalf("refilled token %d rejected", i)
		}
	}
	if ok, _ := l.allow("u:a"); ok {
		t.Fatal("bucket should be empty again")
	}

	r1, ok1 := l.acquireUpload("u:a")
	_, ok2 := l.acquireUpload("u:a")
	_, ok3 := l.acquireUpload("u:a")
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("upload slots: %v %v %v (want true true false)", ok1, ok2, ok3)
	}
	r1()
	r1() // 重复释放不得多还一个槽
	if _, ok := l.acquireUpload("u:a"); !ok {
		t.Fatal("released slot not reusable")
	}
	if _, ok := l.acquireUpload("u:a"); ok {
		t.Fatal("double release must not create an extra slot")
	}

	off := newIdentityLimiter(0, 0)
	for i := 0; i < 1000; i++ {
		if ok, _ := off.allow("u:a"); !ok {
			t.Fatal("disabled limiter must allow everything")
		}
	}
	if _, ok := off.acquireUpload("u:a"); !ok {
		t.Fatal("disabled upload cap must allow")
	}
}
