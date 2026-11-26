use crate::model::{Category, Finding};

/// Sustituye los tramos de las categorías indicadas por `[REDACTED:<regla>]`.
/// Los tramos solapados se unen y se etiquetan con la primera regla.
pub fn apply(text: &str, findings: &[Finding], categories: &[Category]) -> String {
    let mut spans: Vec<(usize, usize, &str)> = findings
        .iter()
        .filter(|f| categories.contains(&f.category) && f.end > f.start)
        .map(|f| (f.start, f.end, f.rule.as_str()))
        .collect();
    spans.sort_by_key(|s| (s.0, std::cmp::Reverse(s.1)));

    let mut merged: Vec<(usize, usize, &str)> = Vec::new();
    for s in spans {
        match merged.last_mut() {
            Some(last) if s.0 < last.1 => last.1 = last.1.max(s.1),
            _ => merged.push(s),
        }
    }

    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for (start, end, rule) in merged {
        out.push_str(&text[pos..start]);
        out.push_str("[REDACTED:");
        out.push_str(rule);
        out.push(']');
        pos = end;
    }
    out.push_str(&text[pos..]);
    out
}
