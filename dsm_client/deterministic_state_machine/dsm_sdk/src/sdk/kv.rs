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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_null() {
        assert_eq!(to_string(&Value::Null), "null");
    }

    #[test]
    fn encode_bool() {
        assert_eq!(to_string(&Value::Bool(true)), "true");
        assert_eq!(to_string(&Value::Bool(false)), "false");
    }

    #[test]
    fn encode_number() {
        assert_eq!(to_string(&Value::Number(42.0)), "42");
        assert_eq!(to_string(&Value::Number(3.14)), "3.14");
        assert_eq!(to_string(&Value::Number(-1.0)), "-1");
    }

    #[test]
    fn encode_string_simple() {
        assert_eq!(to_string(&Value::String("hello".into())), r#""hello""#);
    }

    #[test]
    fn encode_string_escapes_quotes_and_backslash() {
        let val = Value::String(r#"say "hi" \ there"#.into());
        let encoded = to_string(&val);
        assert_eq!(encoded, r#""say \"hi\" \\ there""#);
    }

    #[test]
    fn encode_empty_array() {
        assert_eq!(to_string(&Value::Array(vec![])), "[]");
    }

    #[test]
    fn encode_array_with_elements() {
        let arr = Value::Array(vec![
            Value::Number(1.0),
            Value::Bool(true),
            Value::String("x".into()),
        ]);
        assert_eq!(to_string(&arr), r#"[1,true,"x"]"#);
    }

    #[test]
    fn encode_empty_object() {
        assert_eq!(to_string(&Value::Object(BTreeMap::new())), "{}");
    }

    #[test]
    fn encode_object_deterministic_order() {
        let mut m = BTreeMap::new();
        m.insert("z".into(), Value::Number(1.0));
        m.insert("a".into(), Value::Number(2.0));
        let encoded = to_string(&Value::Object(m));
        assert_eq!(encoded, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn encode_nested_structure() {
        let mut inner = BTreeMap::new();
        inner.insert("key".into(), Value::String("val".into()));
        let outer = Value::Array(vec![Value::Null, Value::Object(inner)]);
        assert_eq!(to_string(&outer), r#"[null,{"key":"val"}]"#);
    }

    #[test]
    fn value_as_str() {
        let s = Value::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));

        assert_eq!(Value::Null.as_str(), None);
        assert_eq!(Value::Bool(true).as_str(), None);
        assert_eq!(Value::Number(1.0).as_str(), None);
    }

    #[test]
    fn from_str_wraps_in_string() {
        let v = from_str("anything").unwrap();
        assert_eq!(v, Value::String("anything".into()));
    }

    #[test]
    fn value_equality() {
        assert_eq!(Value::Null, Value::Null);
        assert_ne!(Value::Bool(true), Value::Bool(false));
        assert_ne!(Value::Number(1.0), Value::Number(2.0));
        assert_eq!(
            Value::String("a".into()),
            Value::String("a".into())
        );
    }
}
