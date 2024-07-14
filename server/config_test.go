package server

import (
	"fmt"
	"os"
	"path"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	yaml "github.com/goccy/go-yaml"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

var (
	yml = `
---
hosts:
  - host: nassen
    ca_file: %s
    users:
      - user: fox
        ek: 000ba1d6910d32dbafb47e1365e8a84606aaefc9bb2404f4f99082f6284a9b33415b
`
)

func TestYaml(t *testing.T) {
	dir := t.TempDir()
	rwc, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("message")
	}

	k, err := keyfile.NewLoadableKey(rwc, tpm2.TPMAlgECC, 256, []byte(nil))
	if err != nil {
		t.Fatalf("message")
	}
	os.WriteFile(path.Join(dir, "id_ecdsa.tmp"), k.Bytes(), 0600)

	var v Config
	if err := yaml.Unmarshal([]byte(fmt.Sprintf(yml, path.Join(dir, "id_ecdsa.tmp"))), &v); err != nil {
		t.Fatalf("failed parsing")
	}
}
