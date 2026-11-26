// Package engine ejecuta el motor de detección (Rust compilado a WebAssembly)
// con wazero, sin cgo. Mantiene un pool de instancias porque una instancia de
// WASM no se puede usar desde varias goroutines a la vez.
package engine

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// El fichero lo genera `make engine` (o scripts/build.ps1) a partir de engine/.
//
//go:embed aegis_engine.wasm
var wasmBytes []byte

// Categorías de hallazgo.
const (
	CategoryInjection   = "injection"
	CategoryObfuscation = "obfuscation"
	CategoryPII         = "pii"
	CategorySecret      = "secret"
)

type Request struct {
	Text             string   `json:"text"`
	Redact           bool     `json:"redact"`
	RedactCategories []string `json:"redact_categories,omitempty"`
}

type Finding struct {
	Category string  `json:"category"`
	Rule     string  `json:"rule"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
	Start    int     `json:"start"`
	End      int     `json:"end"`
}

type Result struct {
	Risk          float64   `json:"risk"`
	Findings      []Finding `json:"findings"`
	Redacted      *string   `json:"redacted,omitempty"`
	EngineVersion string    `json:"engine_version"`
	Error         string    `json:"error,omitempty"`
}

type Engine struct {
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	pool     chan *instance
}

type instance struct {
	mod   api.Module
	alloc api.Function
	free  api.Function
	scan  api.Function
}

// New compila el módulo una vez y crea `size` instancias.
func New(ctx context.Context, size int) (*Engine, error) {
	if size < 1 {
		size = 1
	}
	rt := wazero.NewRuntime(ctx)
	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("compilando el motor WASM: %w", err)
	}
	e := &Engine{rt: rt, compiled: compiled, pool: make(chan *instance, size)}
	for range size {
		inst, err := e.newInstance(ctx)
		if err != nil {
			rt.Close(ctx)
			return nil, err
		}
		e.pool <- inst
	}
	return e, nil
}

func (e *Engine) newInstance(ctx context.Context) (*instance, error) {
	// Nombre vacío: permite instanciar el mismo módulo varias veces.
	mod, err := e.rt.InstantiateModule(ctx, e.compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, fmt.Errorf("instanciando el motor WASM: %w", err)
	}
	inst := &instance{
		mod:   mod,
		alloc: mod.ExportedFunction("aegis_alloc"),
		free:  mod.ExportedFunction("aegis_free"),
		scan:  mod.ExportedFunction("aegis_scan"),
	}
	if inst.alloc == nil || inst.free == nil || inst.scan == nil {
		mod.Close(ctx)
		return nil, errors.New("el módulo WASM no exporta aegis_alloc/aegis_free/aegis_scan")
	}
	if init := mod.ExportedFunction("aegis_init"); init != nil {
		if _, err := init.Call(ctx); err != nil {
			mod.Close(ctx)
			return nil, fmt.Errorf("aegis_init: %w", err)
		}
	}
	return inst, nil
}

// Scan analiza un texto. Es seguro llamarlo desde varias goroutines.
func (e *Engine) Scan(ctx context.Context, req Request) (*Result, error) {
	var inst *instance
	select {
	case inst = <-e.pool:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	res, err := inst.call(ctx, req)
	if err != nil {
		// Una instancia que ha hecho trap queda en estado indefinido: se sustituye.
		inst.mod.Close(ctx)
		if fresh, ferr := e.newInstance(context.Background()); ferr == nil {
			inst = fresh
		} else {
			err = errors.Join(err, ferr)
			inst = nil
		}
	}
	if inst != nil {
		e.pool <- inst
	}
	return res, err
}

func (i *instance) call(ctx context.Context, req Request) (*Result, error) {
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	n := uint64(len(in))
	out, err := i.alloc.Call(ctx, n)
	if err != nil {
		return nil, fmt.Errorf("aegis_alloc: %w", err)
	}
	ptr := out[0]
	defer i.free.Call(ctx, ptr, n)

	if !i.mod.Memory().Write(uint32(ptr), in) {
		return nil, errors.New("escritura fuera de la memoria del WASM")
	}
	out, err = i.scan.Call(ctx, ptr, n)
	if err != nil {
		return nil, fmt.Errorf("aegis_scan: %w", err)
	}
	rptr, rlen := uint32(out[0]>>32), uint32(out[0])
	defer i.free.Call(ctx, uint64(rptr), uint64(rlen))

	view, ok := i.mod.Memory().Read(rptr, rlen)
	if !ok {
		return nil, errors.New("lectura fuera de la memoria del WASM")
	}
	var res Result
	if err := json.Unmarshal(view, &res); err != nil {
		return nil, fmt.Errorf("respuesta del motor: %w", err)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("motor: %s", res.Error)
	}
	return &res, nil
}

func (e *Engine) Close(ctx context.Context) error {
	return e.rt.Close(ctx)
}
