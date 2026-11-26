// Package gateway es el proxy HTTP que se pone delante del LLM: autentica,
// limita, analiza las peticiones y las respuestas con el motor, aplica la
// política y deja todo en el log de auditoría.
package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chachiwachi/llm-aegis/internal/config"
	"github.com/chachiwachi/llm-aegis/internal/engine"
)

// Texto que sustituye a una respuesta bloqueada por la política de salida.
const blockedOutputText = "[llm-aegis: respuesta bloqueada por la política de seguridad]"

// Tamaño máximo de una respuesta completa (no streaming) que se analiza.
const maxResponseBytes = 32 << 20

type Gateway struct {
	cfg         config.Config
	eng         *engine.Engine
	upstream    *url.URL
	upstreamKey string
	client      *http.Client
	keys        [][]byte
	rl          *rateLimiter
	m           *metrics
	log         *slog.Logger
}

func New(cfg config.Config, eng *engine.Engine, log *slog.Logger) (*Gateway, error) {
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	g := &Gateway{
		cfg:      cfg,
		eng:      eng,
		upstream: u,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				ResponseHeaderTimeout: 10 * time.Minute,
				IdleConnTimeout:       90 * time.Second,
				MaxIdleConnsPerHost:   16,
			},
			// No seguir redirecciones del proveedor: podrían sacar la petición fuera.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		rl:  newRateLimiter(cfg.RateLimit.RequestsPerMinute, cfg.RateLimit.Burst),
		m:   newMetrics(),
		log: log,
	}
	if cfg.UpstreamAPIKeyEnv != "" {
		g.upstreamKey = os.Getenv(cfg.UpstreamAPIKeyEnv)
	}
	for _, h := range cfg.APIKeysSHA256 {
		b, _ := hex.DecodeString(h)
		g.keys = append(g.keys, b)
	}
	return g, nil
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /metrics", g.m)
	mux.HandleFunc("POST /v1/chat/completions", g.inspect(openAIChat))
	mux.HandleFunc("POST /v1/completions", g.inspect(openAICompletion))
	mux.HandleFunc("POST /api/chat", g.inspect(ollamaChat))
	mux.HandleFunc("POST /api/generate", g.inspect(ollamaGenerate))
	// Lecturas (listar modelos, etc.) pasan sin análisis. Cualquier otro POST
	// recibe 405: lo que no se sabe inspeccionar no llega al modelo.
	mux.HandleFunc("GET /", g.auth(g.passthrough))
	return mux
}

// ---------- autenticación y límite ----------

type clientHandler func(w http.ResponseWriter, r *http.Request, client string)

func (g *Gateway) auth(next clientHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Api-Key")
		if k, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			key = strings.TrimSpace(k)
		}
		var client string
		switch {
		case key != "":
			sum := hashBytes(key)
			matched := 0
			for _, k := range g.keys {
				matched |= subtle.ConstantTimeCompare(sum, k)
			}
			if matched != 1 {
				writeError(w, http.StatusUnauthorized, "invalid_api_key", "API key no válida", "")
				return
			}
			client = "key:" + hex.EncodeToString(sum[:4])
		case g.cfg.AllowAnonymous:
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			client = "ip:" + host
		default:
			writeError(w, http.StatusUnauthorized, "missing_api_key", "Falta la API key (Authorization: Bearer ...)", "")
			return
		}
		if !g.rl.allow(client) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Demasiadas peticiones", "")
			g.m.add("aegis_requests_total", 1, "route", "any", "action", "rate_limited")
			return
		}
		next(w, r, client)
	}
}

// ---------- inspección ----------

type auditFinding struct {
	Direction string  `json:"direction"`
	Role      string  `json:"role"`
	Category  string  `json:"category"`
	Rule      string  `json:"rule"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
}

type auditRecord struct {
	ID             string
	Client         string
	Route          string
	Model          string
	Actions        []string
	InputRisk      float64
	OutputRisk     float64
	Findings       []auditFinding
	UpstreamStatus int
	Texts          []string
}

func (g *Gateway) inspect(d dialect) http.HandlerFunc {
	return g.auth(func(w http.ResponseWriter, r *http.Request, client string) {
		start := time.Now()
		rec := &auditRecord{ID: newID(), Client: client, Route: d.name}
		w.Header().Set("X-Aegis-Request-Id", rec.ID)
		defer func() { g.audit(rec, time.Since(start)) }()

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.MaxBodyBytes))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				rec.Actions = append(rec.Actions, "rejected_too_large")
				writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "Petición demasiado grande", rec.ID)
				return
			}
			writeError(w, http.StatusBadRequest, "bad_request", "No se pudo leer la petición", rec.ID)
			return
		}
		body, err := decodeJSON(raw)
		if err != nil {
			rec.Actions = append(rec.Actions, "rejected_bad_json")
			writeError(w, http.StatusBadRequest, "bad_request", "El cuerpo no es un objeto JSON válido", rec.ID)
			return
		}
		rec.Model = str(body["model"])

		modified, blocked, err := g.applyPolicy(r.Context(), "input", g.cfg.Input, d.inputs(body), rec)
		if err != nil {
			// Si el motor falla, no se deja pasar nada (fail closed).
			g.log.Error("fallo del motor", "request_id", rec.ID, "error", err)
			rec.Actions = append(rec.Actions, "engine_error")
			writeError(w, http.StatusInternalServerError, "engine_error", "Error interno al analizar la petición", rec.ID)
			return
		}
		if blocked {
			rec.Actions = append(rec.Actions, "blocked_input")
			writeError(w, http.StatusForbidden, "aegis_blocked",
				"Petición bloqueada por llm-aegis: posible prompt injection o datos no permitidos", rec.ID)
			return
		}
		if modified {
			rec.Actions = append(rec.Actions, "redacted_input")
			if raw, err = json.Marshal(body); err != nil {
				writeError(w, http.StatusInternalServerError, "internal", "Error interno", rec.ID)
				return
			}
		}

		resp, err := g.forward(r, raw)
		if err != nil {
			g.m.add("aegis_upstream_errors_total", 1)
			g.log.Warn("proveedor no disponible", "request_id", rec.ID, "error", err)
			rec.Actions = append(rec.Actions, "upstream_error")
			writeError(w, http.StatusBadGateway, "upstream_error", "No se pudo contactar con el modelo", rec.ID)
			return
		}
		defer resp.Body.Close()
		rec.UpstreamStatus = resp.StatusCode

		ct := resp.Header.Get("Content-Type")
		switch {
		case strings.Contains(ct, "text/event-stream") || strings.Contains(ct, "ndjson"):
			g.streamResponse(w, r.Context(), resp, d, rec)
		case resp.StatusCode == http.StatusOK && strings.Contains(ct, "json"):
			g.jsonResponse(w, r.Context(), resp, d, rec)
		default:
			copyResponse(w, resp)
		}
	})
}

// applyPolicy analiza cada texto, redacta lo que toque y dice si hay que bloquear.
func (g *Gateway) applyPolicy(ctx context.Context, dir string, p config.Policy, refs []textRef, rec *auditRecord) (modified, blocked bool, err error) {
	for _, ref := range refs {
		text := ref.get()
		if text == "" {
			continue
		}
		if g.cfg.Audit.IncludeText {
			rec.Texts = append(rec.Texts, dir+"/"+ref.role+": "+text)
		}
		t0 := time.Now()
		res, err := g.eng.Scan(ctx, engine.Request{Text: text, Redact: len(p.Redact) > 0, RedactCategories: p.Redact})
		g.m.observeScan(time.Since(t0))
		if err != nil {
			return modified, false, err
		}
		if dir == "input" {
			rec.InputRisk = max(rec.InputRisk, res.Risk)
		} else {
			rec.OutputRisk = max(rec.OutputRisk, res.Risk)
		}
		for _, f := range res.Findings {
			g.m.add("aegis_findings_total", 1, "direction", dir, "category", f.Category)
			rec.Findings = append(rec.Findings, auditFinding{dir, ref.role, f.Category, f.Rule, f.Severity, f.Score})
			for _, c := range p.BlockCategories {
				if c == f.Category {
					blocked = true
				}
			}
		}
		if p.BlockRisk > 0 && res.Risk >= p.BlockRisk {
			blocked = true
		}
		if blocked {
			return modified, true, nil
		}
		if res.Redacted != nil && *res.Redacted != text {
			ref.set(*res.Redacted)
			modified = true
		}
	}
	return modified, false, nil
}

func (g *Gateway) jsonResponse(w http.ResponseWriter, ctx context.Context, resp *http.Response, d dialect, rec *auditRecord) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error", "Respuesta del modelo incompleta", rec.ID)
		return
	}
	body, err := decodeJSON(data)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error", "Respuesta del modelo no válida", rec.ID)
		return
	}
	refs := d.outputs(body)
	modified, blocked, err := g.applyPolicy(ctx, "output", g.cfg.Output, refs, rec)
	if err != nil {
		g.log.Error("fallo del motor", "request_id", rec.ID, "error", err)
		rec.Actions = append(rec.Actions, "engine_error")
		writeError(w, http.StatusInternalServerError, "engine_error", "Error interno al analizar la respuesta", rec.ID)
		return
	}
	if blocked {
		for _, ref := range refs {
			ref.set(blockedOutputText)
		}
		modified = true
		rec.Actions = append(rec.Actions, "blocked_output")
	} else if modified {
		rec.Actions = append(rec.Actions, "redacted_output")
	}
	if modified {
		if data, err = json.Marshal(body); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Error interno", rec.ID)
			return
		}
	}
	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	w.Write(data)
}

// streamResponse reenvía el streaming tal cual (SSE de OpenAI o NDJSON de
// Ollama) y, al terminar, analiza el texto completo para la auditoría.
// Redactar en streaming queda como mejora futura (ver README).
func (g *Gateway) streamResponse(w http.ResponseWriter, ctx context.Context, resp *http.Response, d dialect, rec *auditRecord) {
	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)

	var acc strings.Builder
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if _, werr := w.Write(line); werr != nil {
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
			if acc.Len() < 1<<20 {
				acc.WriteString(streamDelta(line, d))
			}
		}
		if err != nil {
			break
		}
	}

	rec.Actions = append(rec.Actions, "stream_audited")
	text := acc.String()
	ref := textRef{role: "assistant", get: func() string { return text }, set: func(string) {}}
	audit := g.cfg.Output
	audit.Redact = nil
	if _, violated, err := g.applyPolicy(ctx, "output", audit, []textRef{ref}, rec); err == nil && violated {
		rec.Actions = append(rec.Actions, "stream_policy_violation")
	}
}

func streamDelta(line []byte, d dialect) string {
	line = bytes.TrimSpace(line)
	line = bytes.TrimPrefix(line, []byte("data:"))
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return "" // líneas vacías, comentarios SSE, [DONE]
	}
	chunk, err := decodeJSON(line)
	if err != nil {
		return ""
	}
	return d.delta(chunk)
}

func (g *Gateway) passthrough(w http.ResponseWriter, r *http.Request, _ string) {
	resp, err := g.forward(r, nil)
	if err != nil {
		g.m.add("aegis_upstream_errors_total", 1)
		writeError(w, http.StatusBadGateway, "upstream_error", "No se pudo contactar con el modelo", "")
		return
	}
	defer resp.Body.Close()
	g.m.add("aegis_requests_total", 1, "route", "passthrough", "action", "allowed")
	copyResponse(w, resp)
}

// ---------- proxy ----------

var hopHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

func (g *Gateway) forward(r *http.Request, body []byte) (*http.Response, error) {
	target := *g.upstream
	target.Path = strings.TrimSuffix(g.upstream.Path, "/") + r.URL.Path
	target.RawQuery = r.URL.RawQuery

	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), rd)
	if err != nil {
		return nil, err
	}
	for k, vs := range r.Header {
		switch {
		case hopHeaders[k], k == "Authorization", k == "X-Api-Key", k == "Content-Length", k == "Accept-Encoding", k == "Cookie":
			continue
		}
		req.Header[k] = vs
	}
	if g.upstreamKey != "" {
		req.Header.Set("Authorization", "Bearer "+g.upstreamKey)
	}
	return g.client.Do(req)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if !hopHeaders[k] {
			dst[k] = vs
		}
	}
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ---------- utilidades ----------

func (g *Gateway) audit(rec *auditRecord, dur time.Duration) {
	action := "allowed"
	if len(rec.Actions) > 0 {
		action = strings.Join(rec.Actions, ",")
	}
	g.m.add("aegis_requests_total", 1, "route", rec.Route, "action", action)
	attrs := []any{
		"request_id", rec.ID, "client", rec.Client, "route", rec.Route, "model", rec.Model,
		"action", action, "input_risk", rec.InputRisk, "output_risk", rec.OutputRisk,
		"upstream_status", rec.UpstreamStatus, "duration_ms", dur.Milliseconds(),
	}
	if len(rec.Findings) > 0 {
		attrs = append(attrs, "findings", rec.Findings)
	}
	if len(rec.Texts) > 0 {
		attrs = append(attrs, "texts", rec.Texts)
	}
	g.log.Info("request", attrs...)
}

func decodeJSON(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}
	if body == nil {
		return nil, errors.New("se esperaba un objeto JSON")
	}
	return body, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError responde con el formato de error de OpenAI. No incluye las reglas
// que han saltado para no dar pistas a quien ataca: están en el log con el
// mismo request_id.
func writeError(w http.ResponseWriter, status int, code, msg, requestID string) {
	e := map[string]any{"message": msg, "type": code, "code": code}
	if requestID != "" {
		e["request_id"] = requestID
	}
	writeJSON(w, status, map[string]any{"error": e})
}

func hashBytes(s string) []byte {
	b, _ := hex.DecodeString(config.HashKey(s))
	return b
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
