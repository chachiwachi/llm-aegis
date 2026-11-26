use serde::{Deserialize, Serialize};

/// Familia de un hallazgo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Intento de manipular al modelo (prompt injection, jailbreak, exfiltración).
    Injection,
    /// Texto oculto o codificado para esquivar filtros.
    Obfuscation,
    /// Datos personales (email, teléfono, DNI/NIE, IBAN, tarjeta).
    Pii,
    /// Credenciales y secretos (claves de API, tokens, claves privadas).
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: Category,
    pub rule: String,
    pub severity: Severity,
    /// Confianza de 0 a 1.
    pub score: f32,
    /// Posición en bytes (UTF-8) dentro del texto analizado.
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanRequest {
    pub text: String,
    /// Si es true, la respuesta incluye `redacted` con los datos sensibles tapados.
    #[serde(default)]
    pub redact: bool,
    /// Categorías que se tapan al redactar.
    #[serde(default = "default_redact_categories")]
    pub redact_categories: Vec<Category>,
}

fn default_redact_categories() -> Vec<Category> {
    vec![Category::Pii, Category::Secret]
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// Riesgo de ataque (injection + ofuscación) de 0 a 1.
    pub risk: f32,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<String>,
    pub engine_version: &'static str,
}

impl ScanRequest {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            redact: false,
            redact_categories: default_redact_categories(),
        }
    }

    pub fn with_redaction(mut self) -> Self {
        self.redact = true;
        self
    }
}
