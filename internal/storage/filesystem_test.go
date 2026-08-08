package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePath(t *testing.T) {
	valid := []string{
		"a.md",
		"Notes/hello.md",
		"Attachments/photo.png",
		"深/层/目录/文件.pdf",
		"with space/file name.md",
		".obsidian/app.json",
	}
	for _, p := range valid {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v, want nil", p, err)
		}
	}

	invalid := []string{
		"",
		"..",
		".",
		"../a",
		"a/../b",
		"a/..",
		"/abs",
		"a//b",
		"a/",
		"/",
		"a\\b",
		"C:\\Windows",
		"c:/windows",
		"a\x00b",
		"a\nb",
		strings.Repeat("x", 1025),
	}
	for _, p := range invalid {
		if err := ValidatePath(p); err == nil {
			t.Errorf("ValidatePath(%q) = nil, want error", p)
		}
	}
}

func TestWriteTempPromoteAtomic(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("hello atomic write")
	tmp, hash, size, err := s.WriteTemp("Notes/a.md", bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(content)) {
		t.Fatalf("size = %d", size)
	}
	if len(hash) != 64 {
		t.Fatalf("hash = %q", hash)
	}
	// Promote 之前正式文件不应存在
	if _, err := s.Open("Notes/a.md"); err == nil {
		t.Fatal("file exists before promote")
	}
	if err := s.Promote(tmp, "Notes/a.md"); err != nil {
		t.Fatal(err)
	}
	f, err := s.Open("Notes/a.md")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestRemoveCleansEmptyDirs(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "vault")
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	tmp, _, _, err := s.WriteTemp("a/b/c.md", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Promote(tmp, "a/b/c.md"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("a/b/c.md"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "a")); !os.IsNotExist(err) {
		t.Fatal("empty parent dirs not cleaned")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("root must not be removed")
	}
	// 删除不存在的文件应当成功
	if err := s.Remove("never/existed.md"); err != nil {
		t.Fatal(err)
	}
}

func TestCleanTempFiles(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "vault")
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(root, ".obsync-tmp-orphan")
	if err := os.WriteFile(orphan, []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.CleanTempFiles(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan temp file not cleaned")
	}
}
