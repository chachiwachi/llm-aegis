//! Credenciales y secretos.

use std::sync::LazyLock;

use super::{Rule, finding, rule};
use crate::model::{Category, Finding, Severity::*};

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        rule(
            "private_key",
            r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )*PRIVATE KEY-----|\z)",
            0.99,
            Critical,
        ),
        rule("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0.95, Critical),
        rule("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b", 0.95, Critical),
        rule("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", 0.95, Critical),
        rule("openai_key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}", 0.9, Critical),
        rule("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", 0.95, Critical),
        rule("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", 0.9, Critical),
        rule("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", 0.95, Critical),
        rule("telegram_bot_token", r"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b", 0.9, Critical),
        rule(
            "jwt",
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            0.85,
            High,
        ),
        rule(
            "password_assignment",
            r#"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|contraseña|contrasena|clave)\b["']?\s*[:=]\s*["']?([^\s"',;]{8,})"#,
            0.8,
            High,
        )
        .with_group(2),
    ]
});

pub fn warm() {
    LazyLock::force(&RULES);
}

pub fn detect(text: &str, out: &mut Vec<Finding>) {
    for r in RULES.iter() {
        for caps in r.re.captures_iter(text) {
            let Some(m) = caps.get(r.group) else { continue };
            if r.id == "password_assignment" && !looks_secret(m.as_str()) {
                continue;
            }
            out.push(finding(
                Category::Secret,
                r.id,
                r.severity,
                r.score,
                m.start(),
                m.end(),
            ));
        }
    }
}

/// Descarta valores de ejemplo ("xxxxxxxx", "${TOKEN}", "<tu-clave>").
fn looks_secret(v: &str) -> bool {
    if v.starts_with("${") || v.starts_with('<') || v.starts_with("{{") {
        return false;
    }
    shannon_entropy(v) >= 2.8
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        detect(text, &mut out);
        out.into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn claves_de_proveedores() {
        assert_eq!(rules("AKIAIOSFODNN7EXAMPLE"), vec!["aws_access_key"]);
        assert_eq!(
            rules("token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
            vec!["github_token"]
        );
        let r = rules("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz");
        assert!(r.contains(&"anthropic_key".into()), "{r:?}");
    }

    #[test]
    fn clave_privada_completa() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(rules(pem), vec!["private_key"]);
    }

    #[test]
    fn asignacion_de_password_filtra_ejemplos() {
        assert_eq!(
            rules("password: Tr0ub4dor&3xyz"),
            vec!["password_assignment"]
        );
        assert!(rules("password: xxxxxxxxxx").is_empty());
        assert!(rules("api_key=${OPENAI_KEY}").is_empty());
    }
}
