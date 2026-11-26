package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSinClavesFalla(t *testing.T) {
	if err := Default().Validate(); err == nil {
		t.Fatal("sin API keys ni allow_anonymous debería fallar")
	}
}

func TestClavesPorEntorno(t *testing.T) {
	t.Setenv("AEGIS_API_KEYS", "uno, dos")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.APIKeysSHA256) != 2 || cfg.APIKeysSHA256[0] != HashKey("uno") {
		t.Fatalf("claves: %v", cfg.APIKeysSHA256)
	}
}

func TestEjemploEsValido(t *testing.T) {
	t.Setenv("AEGIS_API_KEYS", "x")
	if _, err := Load(filepath.Join("..", "..", "aegis.example.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestCampoDesconocidoFalla(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte("allow_anonymous: true\nblock_rsik: 0.5\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("una errata en la config debería dar error")
	}
}

func TestCategoriaDesconocidaFalla(t *testing.T) {
	cfg := Default()
	cfg.AllowAnonymous = true
	cfg.Input.Redact = []string{"pii", "emails"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("categoría desconocida debería fallar")
	}
}
