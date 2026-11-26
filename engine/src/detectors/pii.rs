//! Datos personales. Los identificadores con dígito de control (DNI/NIE,
//! IBAN, tarjetas) se validan para evitar falsos positivos.

use std::sync::LazyLock;

use super::{Rule, finding, rule};
use crate::model::{Category, Finding, Severity::*};

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        rule(
            "email",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            0.6,
            Medium,
        ),
        rule(
            "phone_es",
            r"(?:\+34[\s.-]?)?\b[6-9][0-9]{2}(?:[\s.-]?[0-9]{3}[\s.-]?[0-9]{3}|[\s.-]?[0-9]{2}[\s.-]?[0-9]{2}[\s.-]?[0-9]{2})\b",
            0.5,
            Medium,
        ),
        rule(
            "phone_intl",
            r"\+[1-9](?:[\s.-]?[0-9]){7,14}\b",
            0.5,
            Medium,
        ),
        rule("dni", r"\b[0-9]{8}[\s-]?[A-Za-z]\b", 0.8, High),
        rule(
            "nie",
            r"\b[XYZxyz][\s-]?[0-9]{7}[\s-]?[A-Za-z]\b",
            0.8,
            High,
        ),
        rule(
            "iban",
            r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b",
            0.9,
            High,
        ),
        rule(
            "credit_card",
            r"\b[0-9](?:[ -]?[0-9]){12,18}\b",
            0.95,
            Critical,
        ),
    ]
});

pub fn warm() {
    LazyLock::force(&RULES);
}

pub fn detect(text: &str, out: &mut Vec<Finding>) {
    for r in RULES.iter() {
        for m in r.re.find_iter(text) {
            let s = m.as_str();
            let valid = match r.id {
                "dni" => valid_dni(s),
                "nie" => valid_nie(s),
                "iban" => valid_iban(s),
                "credit_card" => valid_card(s),
                _ => true,
            };
            if valid {
                out.push(finding(
                    Category::Pii,
                    r.id,
                    r.severity,
                    r.score,
                    m.start(),
                    m.end(),
                ));
            }
        }
    }
}

const DNI_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

fn alnum_upper(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn dni_letter_ok(number: u32, letter: char) -> bool {
    DNI_LETTERS[(number % 23) as usize] as char == letter
}

fn valid_dni(s: &str) -> bool {
    let s = alnum_upper(s);
    let (num, letter) = s.split_at(8);
    num.parse::<u32>()
        .is_ok_and(|n| dni_letter_ok(n, letter.chars().next().unwrap_or(' ')))
}

fn valid_nie(s: &str) -> bool {
    let s = alnum_upper(s);
    let prefix = match s.chars().next() {
        Some('X') => '0',
        Some('Y') => '1',
        Some('Z') => '2',
        _ => return false,
    };
    let num = format!("{prefix}{}", &s[1..8]);
    num.parse::<u32>()
        .is_ok_and(|n| dni_letter_ok(n, s.chars().nth(8).unwrap_or(' ')))
}

fn valid_iban(s: &str) -> bool {
    let s = alnum_upper(s);
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let v = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

fn valid_card(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) || digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
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
    fn dni_y_nie_validan_letra() {
        assert_eq!(rules("mi DNI es 12345678Z"), vec!["dni"]);
        assert!(rules("mi DNI es 12345678A").is_empty());
        assert_eq!(rules("NIE X1234567L"), vec!["nie"]);
    }

    #[test]
    fn iban_valida_mod97() {
        assert_eq!(rules("IBAN: ES91 2100 0418 4502 0005 1332"), vec!["iban"]);
        assert!(rules("IBAN: ES00 2100 0418 4502 0005 1332").is_empty());
    }

    #[test]
    fn tarjeta_valida_luhn() {
        assert!(rules("tarjeta 4111 1111 1111 1111").contains(&"credit_card".into()));
        assert!(!rules("pedido 4111 1111 1111 1112").contains(&"credit_card".into()));
    }

    #[test]
    fn email_y_telefono() {
        assert_eq!(rules("escribe a ana.lopez@ejemplo.es"), vec!["email"]);
        assert!(rules("llámame al 612 34 56 78").contains(&"phone_es".into()));
        assert!(
            rules("llámame al +34 612345678")
                .iter()
                .any(|r| r.starts_with("phone"))
        );
    }
}
