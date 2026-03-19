//! Minimal, JSON-free key/value encoding helpers for SDK storage.
//! This intentionally avoids serde/serde_json per project policy.
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        if let Value::String(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
}

// Deterministic, simple textual encoding (not JSON; no escaping guarantees beyond quotes/backslash).
pub fn to_string(v: &Value) -> String {
    fn enc(v: &Value, out: &mut String) {
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(&n.to_string()),
            Value::String(s) => {
                out.push('"');
                for ch in s.chars() {
                    if ch == '"' || ch == '\\' {
                        out.push('\\');
                    }
                    out.push(ch);
                }
                out.push('"');
            }
            Value::Array(a) => {
                out.push('[');
                let mut first = true;
                for x in a {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    enc(x, out);
                }
                out.push(']');
            }
            Value::Object(m) => {
                out.push('{');
                let mut first = true;
                for (k, v) in m {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    out.push('"');
                    out.push_str(k);
                    out.push('"');
                    out.push(':');
                    enc(v, out);
                }
                out.push('}');
            }
        }
    }
    let mut s = String::new();
    enc(v, &mut s);
    s
}

// Parser deliberately not implemented—policy is binary-first; callers should not depend on parsing.
pub fn from_str(s: &str) -> Result<Value, String> {
    Ok(Value::String(s.to_owned()))
}
