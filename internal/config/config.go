// Package config carga la configuración YAML de llm-aegis.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen string `yaml:"listen"`
	// URL base del proveedor: Ollama (http://host:11434) o API compatible con OpenAI.
	Upstream string `yaml:"upstream"`
	// Variable de entorno con la API key del proveedor (se envía como Bearer).
	UpstreamAPIKeyEnv string `yaml:"upstream_api_key_env"`

	// Hashes SHA-256 (hex) de las API keys de los clientes. Generar con `aegis hash-key`.
	APIKeysSHA256 []string `yaml:"api_keys_sha256"`
	// Permitir peticiones sin API key (solo para pruebas en local).
	AllowAnonymous bool `yaml:"allow_anonymous"`

	RateLimit RateLimit `yaml:"rate_limit"`
	Input     Policy    `yaml:"input"`
	Output    Policy    `yaml:"output"`

	MaxBodyBytes   int64 `yaml:"max_body_bytes"`
	EnginePoolSize int   `yaml:"engine_pool_size"`
	Audit          Audit `yaml:"audit"`
}

type RateLimit struct {
	// 0 desactiva el límite.
	RequestsPerMinute float64 `yaml:"requests_per_minute"`
	Burst             int     `yaml:"burst"`
}

// Policy decide qué hacer con lo que detecta el motor en una dirección.
type Policy struct {
	// Bloquear si el riesgo de ataque es >= este valor (0 = nunca).
	BlockRisk float64 `yaml:"block_risk"`
	// Bloquear si aparece cualquier hallazgo de estas categorías.
	BlockCategories []string `yaml:"block_categories"`
	// Categorías que se tapan antes de seguir (pii, secret).
	Redact []string `yaml:"redact"`
}

type Audit struct {
	// Guarda el texto original en el log. Ojo: el log contendrá datos sensibles.
	IncludeText bool `yaml:"include_text"`
}

func Default() Config {
	return Config{
		Listen:         ":8080",
		Upstream:       "http://127.0.0.1:11434",
		RateLimit:      RateLimit{RequestsPerMinute: 60, Burst: 10},
		Input:          Policy{BlockRisk: 0.85, Redact: []string{"pii", "secret"}},
		Output:         Policy{Redact: []string{"secret"}},
		MaxBodyBytes:   1 << 20,
		EnginePoolSize: 4,
	}
}

// Load lee el fichero (si path no está vacío) sobre los valores por defecto y
// aplica las variables de entorno AEGIS_UPSTREAM, AEGIS_LISTEN y AEGIS_API_KEYS.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return cfg, fmt.Errorf("%s: %w", path, err)
		}
	}
	if v := os.Getenv("AEGIS_UPSTREAM"); v != "" {
		cfg.Upstream = v
	}
	if v := os.Getenv("AEGIS_LISTEN"); v != "" {
		cfg.Listen = v
	}
	// Claves en claro por entorno (cómodo en Docker); se guardan solo como hash.
	for _, k := range strings.Split(os.Getenv("AEGIS_API_KEYS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			cfg.APIKeysSHA256 = append(cfg.APIKeysSHA256, HashKey(k))
		}
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	u, err := url.Parse(c.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("upstream inválido: %q", c.Upstream)
	}
	if len(c.APIKeysSHA256) == 0 && !c.AllowAnonymous {
		return errors.New("no hay API keys (api_keys_sha256 o AEGIS_API_KEYS); usa allow_anonymous: true solo para pruebas")
	}
	for _, h := range c.APIKeysSHA256 {
		if b, err := hex.DecodeString(h); err != nil || len(b) != sha256.Size {
			return fmt.Errorf("api_keys_sha256: %q no es un SHA-256 en hex", h)
		}
	}
	for _, p := range []Policy{c.Input, c.Output} {
		if p.BlockRisk < 0 || p.BlockRisk > 1 {
			return errors.New("block_risk debe estar entre 0 y 1")
		}
		for _, cat := range append(append([]string{}, p.BlockCategories...), p.Redact...) {
			switch cat {
			case "injection", "obfuscation", "pii", "secret":
			default:
				return fmt.Errorf("categoría desconocida: %q", cat)
			}
		}
	}
	if c.MaxBodyBytes <= 0 {
		return errors.New("max_body_bytes debe ser > 0")
	}
	return nil
}

func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
