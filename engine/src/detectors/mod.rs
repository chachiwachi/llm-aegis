pub mod injection;
pub mod obfuscation;
pub mod pii;
pub mod secrets;

use regex::Regex;

use crate::model::{Category, Finding, Severity};

/// Regla basada en una expresión regular.
pub struct Rule {
    pub id: &'static str,
    pub re: Regex,
    pub score: f32,
    pub severity: Severity,
    /// Grupo de captura que marca el tramo sensible (0 = coincidencia completa).
    pub group: usize,
}

pub fn rule(id: &'static str, pattern: &str, score: f32, severity: Severity) -> Rule {
    Rule {
        id,
        re: Regex::new(pattern).unwrap_or_else(|e| panic!("regla {id} inválida: {e}")),
        score,
        severity,
        group: 0,
    }
}

impl Rule {
    pub fn with_group(mut self, group: usize) -> Self {
        self.group = group;
        self
    }
}

pub fn finding(
    category: Category,
    rule: impl Into<String>,
    severity: Severity,
    score: f32,
    start: usize,
    end: usize,
) -> Finding {
    Finding {
        category,
        rule: rule.into(),
        severity,
        score,
        start,
        end,
    }
}

/// Fuerza la compilación de todas las reglas (se llama al arrancar la instancia).
pub fn warm() {
    injection::warm();
    obfuscation::warm();
    pii::warm();
    secrets::warm();
}
