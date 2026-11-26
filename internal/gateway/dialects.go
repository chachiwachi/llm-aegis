package gateway

// Un dialecto sabe dónde está el texto en las peticiones y respuestas de cada
// API (OpenAI u Ollama). Los cuerpos se manejan como JSON genérico para no
// perder campos que el gateway no conoce.

type textRef struct {
	role string
	get  func() string
	set  func(string)
}

type dialect struct {
	name string
	// Textos no confiables de la petición (usuario, herramientas).
	inputs func(body map[string]any) []textRef
	// Textos generados por el modelo en una respuesta completa.
	outputs func(body map[string]any) []textRef
	// Texto de un fragmento de streaming (para auditar).
	delta func(chunk map[string]any) string
}

var (
	openAIChat = dialect{
		name:    "openai_chat",
		inputs:  func(b map[string]any) []textRef { return messageRefs(b["messages"]) },
		outputs: func(b map[string]any) []textRef { return choiceRefs(b, "message") },
		delta: func(c map[string]any) string {
			var s string
			for _, ch := range asSlice(c["choices"]) {
				if d, ok := asMap(ch)["delta"].(map[string]any); ok {
					s += str(d["content"])
				}
			}
			return s
		},
	}
	openAICompletion = dialect{
		name:    "openai_completion",
		inputs:  func(b map[string]any) []textRef { return promptRefs(b, "prompt") },
		outputs: func(b map[string]any) []textRef { return choiceTextRefs(b) },
		delta: func(c map[string]any) string {
			var s string
			for _, ch := range asSlice(c["choices"]) {
				s += str(asMap(ch)["text"])
			}
			return s
		},
	}
	ollamaChat = dialect{
		name:   "ollama_chat",
		inputs: func(b map[string]any) []textRef { return messageRefs(b["messages"]) },
		outputs: func(b map[string]any) []textRef {
			if m, ok := b["message"].(map[string]any); ok {
				return []textRef{fieldRef(m, "content", "assistant")}
			}
			return nil
		},
		delta: func(c map[string]any) string { return str(asMap(c["message"])["content"]) },
	}
	ollamaGenerate = dialect{
		name:    "ollama_generate",
		inputs:  func(b map[string]any) []textRef { return promptRefs(b, "prompt") },
		outputs: func(b map[string]any) []textRef { return []textRef{fieldRef(b, "response", "assistant")} },
		delta:   func(c map[string]any) string { return str(c["response"]) },
	}
)

// Roles cuyo contenido no es de confianza. El mensaje "system" lo pone la
// aplicación, no el usuario; el historial del asistente ya pasó por la salida.
var untrustedRoles = map[string]bool{"user": true, "tool": true, "function": true}

func messageRefs(v any) []textRef {
	var refs []textRef
	for _, m := range asSlice(v) {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		role := str(msg["role"])
		if !untrustedRoles[role] {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			refs = append(refs, fieldRef(msg, "content", role))
		case []any: // OpenAI: [{type: text, text: ...}, {type: image_url, ...}]
			for _, p := range content {
				if part, ok := p.(map[string]any); ok && str(part["type"]) == "text" {
					refs = append(refs, fieldRef(part, "text", role))
				}
			}
		}
	}
	return refs
}

func promptRefs(b map[string]any, key string) []textRef {
	switch p := b[key].(type) {
	case string:
		return []textRef{fieldRef(b, key, "user")}
	case []any:
		var refs []textRef
		for i := range p {
			if _, ok := p[i].(string); ok {
				refs = append(refs, textRef{
					role: "user",
					get:  func() string { return p[i].(string) },
					set:  func(s string) { p[i] = s },
				})
			}
		}
		return refs
	}
	return nil
}

func choiceRefs(b map[string]any, key string) []textRef {
	var refs []textRef
	for _, ch := range asSlice(b["choices"]) {
		if m, ok := asMap(ch)[key].(map[string]any); ok {
			if _, ok := m["content"].(string); ok {
				refs = append(refs, fieldRef(m, "content", "assistant"))
			}
		}
	}
	return refs
}

func choiceTextRefs(b map[string]any) []textRef {
	var refs []textRef
	for _, ch := range asSlice(b["choices"]) {
		if m := asMap(ch); m != nil {
			if _, ok := m["text"].(string); ok {
				refs = append(refs, fieldRef(m, "text", "assistant"))
			}
		}
	}
	return refs
}

func fieldRef(m map[string]any, key, role string) textRef {
	return textRef{
		role: role,
		get:  func() string { return str(m[key]) },
		set:  func(s string) { m[key] = s },
	}
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
