package boostx_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestSpecMirror checks that testdata/spec is a byte-for-byte copy of vectors/
// in the boostx-partner-sdk-spec checkout that BOOSTX_SPEC_REPO names.
func TestSpecMirror(t *testing.T) {
	repo := os.Getenv("BOOSTX_SPEC_REPO")
	if repo == "" {
		t.Skip("BOOSTX_SPEC_REPO is not set")
	}
	want := specMirrorFiles(t, filepath.Join(repo, "vectors"))
	got := specMirrorFiles(t, filepath.Join("..", "testdata", "spec"))
	for name, b := range want {
		if g, ok := got[name]; !ok {
			t.Errorf("missing from testdata/spec: %s", name)
		} else if !bytes.Equal(g, b) {
			t.Errorf("differs from the spec: %s", name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("not in the spec: %s", name)
		}
	}
}

func specMirrorFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	fsys := os.DirFS(dir)
	files := map[string][]byte{}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files[name], err = fs.ReadFile(fsys, name)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	return files
}
