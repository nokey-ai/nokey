package metadata

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	return NewStore(filepath.Join(dir, "meta.json"))
}

func TestRecordSet_CreatesEntry(t *testing.T) {
	s := testStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	NowFn = func() time.Time { return now }
	t.Cleanup(func() { NowFn = func() time.Time { return time.Now().UTC() } })

	if err := s.RecordSet("API_KEY"); err != nil {
		t.Fatal(err)
	}

	meta, err := s.GetMeta("API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil {
		t.Fatal("expected metadata, got nil")
	}
	if meta.SetCount != 1 {
		t.Fatalf("expected SetCount=1, got %d", meta.SetCount)
	}
	if !meta.CreatedAt.Equal(now) {
		t.Fatalf("expected CreatedAt=%v, got %v", now, meta.CreatedAt)
	}
}

func TestRecordSet_IncrementsCount(t *testing.T) {
	s := testStore(t)

	_ = s.RecordSet("KEY")
	_ = s.RecordSet("KEY")
	_ = s.RecordSet("KEY")

	meta, _ := s.GetMeta("KEY")
	if meta.SetCount != 3 {
		t.Fatalf("expected SetCount=3, got %d", meta.SetCount)
	}
}

func TestRecordAccess_UpdatesLastAccessed(t *testing.T) {
	s := testStore(t)

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	NowFn = func() time.Time { return t1 }
	_ = s.RecordSet("KEY")

	NowFn = func() time.Time { return t2 }
	_ = s.RecordAccess([]string{"KEY"})

	t.Cleanup(func() { NowFn = func() time.Time { return time.Now().UTC() } })

	meta, _ := s.GetMeta("KEY")
	if !meta.LastAccessed.Equal(t2) {
		t.Fatalf("expected LastAccessed=%v, got %v", t2, meta.LastAccessed)
	}
}

func TestRemove_DeletesEntry(t *testing.T) {
	s := testStore(t)
	_ = s.RecordSet("KEY")

	if err := s.Remove("KEY"); err != nil {
		t.Fatal(err)
	}

	meta, _ := s.GetMeta("KEY")
	if meta != nil {
		t.Fatal("expected nil after removal")
	}
}

func TestListStale(t *testing.T) {
	s := testStore(t)

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	NowFn = func() time.Time { return old }
	_ = s.RecordSet("OLD_KEY")

	NowFn = func() time.Time { return recent }
	_ = s.RecordSet("NEW_KEY")

	stale, err := s.ListStale(30 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { NowFn = func() time.Time { return time.Now().UTC() } })

	if len(stale) != 1 || stale[0] != "OLD_KEY" {
		t.Fatalf("expected [OLD_KEY], got %v", stale)
	}
}

func TestPersistence_AcrossInstances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.json")

	s1 := NewStore(path)
	_ = s1.RecordSet("KEY")

	s2 := NewStore(path)
	meta, err := s2.GetMeta("KEY")
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil || meta.SetCount != 1 {
		t.Fatal("expected metadata to persist across instances")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "nonexistent.json"))

	meta, err := s.GetMeta("KEY")
	if err != nil {
		t.Fatal(err)
	}
	if meta != nil {
		t.Fatal("expected nil for missing file")
	}
}

func TestLoad_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.json")
	os.WriteFile(path, []byte("not json"), 0600)

	s := NewStore(path)
	_, err := s.GetMeta("KEY")
	if err == nil {
		t.Fatal("expected error for corrupt file")
	}
}
