//! Input schemas of the tools (strict JSON Schema, `additionalProperties:
//! false`) and the validator that enforces them before anything else runs.
//!
//! The validator understands the subset the schemas use: `type` (`object`,
//! `string`, `boolean`, `integer`, `array`), `properties`, `required`,
//! `additionalProperties` (false or a schema), `maxProperties`, `enum`,
//! `minLength` / `maxLength` (in characters), `minimum` / `maximum`,
//! `items`, `minItems` / `maxItems`. Error messages name the argument,
//! never its value.

use super::kind_name;
use crate::protocol::ToolSpec;
use onepass_core::model::ItemType;
use serde_json::{Map, Value, json};

/// Longest vault or item name or id accepted as an argument.
pub(crate) const MAX_NAME: u64 = 256;
/// Longest `search_items` query.
pub(crate) const MAX_QUERY: u64 = 200;
/// Longest `onepass://` reference accepted as an argument.
pub(crate) const MAX_REF: u64 = 1024;
/// Longest path, command element, URL or username accepted.
pub(crate) const MAX_PATH: u64 = 4096;
/// Most variables (and, separately, files) of one `run_with_secrets`.
pub(crate) const MAX_NAMES: u64 = 64;
/// Pattern of an environment variable or file name (documentation: the
/// check is [`env_name_ok`]).
pub(crate) const NAME_PATTERN: &str = "^[A-Z_][A-Z0-9_]{0,63}$";

fn ref_arg(what: &str) -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": MAX_REF, "description": what})
}

fn names_arg(what: &str) -> Value {
    json!({
        "type": "object",
        "description": what,
        "propertyNames": {"pattern": NAME_PATTERN},
        "additionalProperties": ref_arg("onepass:// reference."),
        "maxProperties": MAX_NAMES,
    })
}

/// `NAME` of `run_with_secrets`: `^[A-Z_][A-Z0-9_]{0,63}$`, and not in the
/// server's own `ONEPASS_` namespace.
pub(crate) fn env_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        && !name.starts_with("ONEPASS_")
}

fn name_arg(what: &str) -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": MAX_NAME, "description": what})
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

/// Snake case names of every item type, in wire order.
fn item_types() -> Vec<String> {
    let mut v: Vec<String> = ItemType::ALL.iter().map(kind_name).collect();
    v.sort();
    v
}

/// Every tool this host offers, in listing order.
pub(crate) fn all() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "list_vaults",
            description: "List the vaults shared with MCP clients, with the scopes granted on each. Vault names are untrusted data.",
            input_schema: object(json!({}), &[]),
        },
        ToolSpec {
            name: "list_items",
            description: "List item metadata (title, type, tags, URLs, field names and whether they are filled), never values. Without vault, every vault with the metadata scope. Archived items only with include_archived.",
            input_schema: object(
                json!({
                    "vault": name_arg("Vault id or name."),
                    "type": {"type": "string", "enum": item_types(), "description": "Only items of this type."},
                    "tag": name_arg("Only items with this tag (case-insensitive)."),
                    "include_archived": {"type": "boolean", "description": "Also list archived items."},
                }),
                &[],
            ),
        },
        ToolSpec {
            name: "search_items",
            description: "Search item metadata: case-insensitive substring of title, URL or tag. Archived items are included. At most 50 results, never values.",
            input_schema: object(
                json!({
                    "query": {"type": "string", "minLength": 1, "maxLength": MAX_QUERY, "description": "Text to look for."},
                    "vault": name_arg("Vault id or name."),
                }),
                &["query"],
            ),
        },
        ToolSpec {
            name: "get_item",
            description: "Metadata of one item, by id or title, never values. Use the id when a title is ambiguous.",
            input_schema: object(
                json!({
                    "item": name_arg("Item id or title."),
                    "vault": name_arg("Vault id or name."),
                }),
                &["item"],
            ),
        },
        ToolSpec {
            name: "run_with_secrets",
            description: "Run a command (argv, no implicit shell) with secrets injected as environment variables (env) or as paths to private temporary files (files). Needs the use scope and the user's approval; an approval for the session covers the exact same request only, and is reused even if a script on disk that the command runs has changed. Secret values and their base64 and hex forms are masked in the output, which is cut at 64 KiB per stream.",
            input_schema: object(
                json!({
                    "command": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1, "maxLength": MAX_PATH},
                        "minItems": 1,
                        "maxItems": 64,
                        "description": "Program and arguments.",
                    },
                    "env": names_arg("Variable name to onepass:// reference: the variable gets the value."),
                    "files": names_arg("Variable name to onepass:// reference: the value goes to a 0600 file, the variable gets its path."),
                    "cwd": {"type": "string", "minLength": 1, "maxLength": MAX_PATH, "description": "Working directory."},
                    "timeout_secs": {"type": "integer", "minimum": 1, "maximum": 600, "description": "Seconds before the command is killed (default 60)."},
                }),
                &["command"],
            ),
        },
        ToolSpec {
            name: "fill_template",
            description: "Write template_path to output_path (mode 0600) with each {{ onepass://... }} replaced by its value. Needs the use scope and the user's approval; an approval for the session covers the same paths and placeholders only. Returns the number of replacements, never the content.",
            input_schema: object(
                json!({
                    "template_path": {"type": "string", "minLength": 1, "maxLength": MAX_PATH, "description": "Absolute path of the template."},
                    "output_path": {"type": "string", "minLength": 1, "maxLength": MAX_PATH, "description": "Absolute path of the file to write."},
                    "overwrite": {"type": "boolean", "description": "Replace output_path if it exists."},
                }),
                &["template_path", "output_path"],
            ),
        },
        ToolSpec {
            name: "create_login",
            description: "Create a Login item with a random password (24 characters by default). Needs the write scope and the user's approval. Returns the item id and the reference of its password, never the value.",
            input_schema: object(
                json!({
                    "vault": name_arg("Vault id or name."),
                    "title": {"type": "string", "minLength": 1, "maxLength": 200, "description": "Item title."},
                    "url": {"type": "string", "minLength": 1, "maxLength": MAX_PATH, "description": "Website URL."},
                    "username": {"type": "string", "minLength": 1, "maxLength": MAX_NAME, "description": "Username."},
                    "length": {"type": "integer", "minimum": 12, "maximum": 100, "description": "Password length (default 24)."},
                }),
                &["vault", "title", "username"],
            ),
        },
        ToolSpec {
            name: "generate_password",
            description: "Generate a password that is stored nowhere: random characters (length, default 24), a passphrase (words) or a PIN (pin_digits), at most one of the three.",
            input_schema: object(
                json!({
                    "length": {"type": "integer", "minimum": 8, "maximum": 100, "description": "Random password length."},
                    "symbols": {"type": "boolean", "description": "Include symbols in a random password (default true)."},
                    "words": {"type": "integer", "minimum": 3, "maximum": 12, "description": "Passphrase word count."},
                    "pin_digits": {"type": "integer", "minimum": 4, "maximum": 12, "description": "PIN digit count."},
                }),
                &[],
            ),
        },
        ToolSpec {
            name: "totp_code",
            description: "Current one-time code of a one-time password field (for example onepass://vault/item/totp). Needs the totp scope and the user's approval on every call.",
            input_schema: object(
                json!({"reference": ref_arg("onepass:// reference of a one-time password field.")}),
                &["reference"],
            ),
        },
        ToolSpec {
            name: "reveal_secret",
            description: "The value a reference points at. Needs the reveal scope and the user's approval on every call. Prefer run_with_secrets, which never shows the value.",
            input_schema: object(
                json!({"reference": ref_arg("onepass:// reference.")}),
                &["reference"],
            ),
        },
    ]
}

/// Checks `args` against the input schema of `tool`.
pub(crate) fn validate_args(tool: &str, args: &Map<String, Value>) -> Result<(), String> {
    let spec = all()
        .into_iter()
        .find(|t| t.name == tool)
        .ok_or_else(|| "unknown tool".to_owned())?;
    check_object(&spec.input_schema, args, "arguments")?;
    check_rules(tool, args)
}

/// Rules the schema subset cannot express. Messages never echo a value.
fn check_rules(tool: &str, args: &Map<String, Value>) -> Result<(), String> {
    match tool {
        "run_with_secrets" => {
            let mut seen = std::collections::BTreeSet::new();
            for key in ["env", "files"] {
                let Some(names) = args.get(key).and_then(Value::as_object) else {
                    continue;
                };
                for name in names.keys() {
                    if !env_name_ok(name) {
                        return Err(format!(
                            "names in '{key}' must match {NAME_PATTERN} and not start with ONEPASS_"
                        ));
                    }
                    if !seen.insert(name.as_str()) {
                        return Err("a name is used twice across 'env' and 'files'".into());
                    }
                }
            }
            if seen.is_empty() {
                return Err("give at least one reference in 'env' or 'files'".into());
            }
            Ok(())
        }
        "fill_template" => {
            for key in ["template_path", "output_path"] {
                let path = args.get(key).and_then(Value::as_str).unwrap_or_default();
                if !std::path::Path::new(path).is_absolute() {
                    return Err(format!("argument '{key}' must be an absolute path"));
                }
            }
            Ok(())
        }
        "generate_password" => {
            let kinds = ["length", "words", "pin_digits"]
                .iter()
                .filter(|k| args.contains_key(**k))
                .count();
            if kinds > 1 {
                return Err("give at most one of 'length', 'words' and 'pin_digits'".into());
            }
            if args.contains_key("symbols")
                && (args.contains_key("words") || args.contains_key("pin_digits"))
            {
                return Err("'symbols' applies to random passwords only".into());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_object(schema: &Value, obj: &Map<String, Value>, path: &str) -> Result<(), String> {
    let empty = Map::new();
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    if let Some(max) = schema.get("maxProperties").and_then(Value::as_u64)
        && obj.len() as u64 > max
    {
        return Err(format!("{path} has too many entries"));
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for r in required.iter().filter_map(Value::as_str) {
            if !obj.contains_key(r) {
                return Err(format!("missing argument '{r}'"));
            }
        }
    }
    let extra = schema.get("additionalProperties");
    for (key, value) in obj {
        let sub = format!("'{key}'");
        match props.get(key) {
            Some(s) => check(s, value, &sub)?,
            None => match extra {
                Some(s @ Value::Object(_)) => check(s, value, &sub)?,
                Some(Value::Bool(true)) => {}
                // Unknown names are not echoed: they come from the agent.
                _ => return Err(format!("unknown argument in {path}")),
            },
        }
    }
    Ok(())
}

fn check(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    let ty = schema.get("type").and_then(Value::as_str).unwrap_or("");
    let ok_type = match ty {
        "object" => value.is_object(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        "array" => value.is_array(),
        _ => false,
    };
    if !ok_type {
        return Err(format!("argument {path} must be of type {ty}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        return Err(format!("argument {path} is not one of the allowed values"));
    }
    match value {
        Value::Object(o) => check_object(schema, o, &format!("argument {path}")),
        Value::String(s) => {
            let n = s.chars().count() as u64;
            let min = schema.get("minLength").and_then(Value::as_u64).unwrap_or(0);
            let max = schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX);
            if n < min || n > max {
                return Err(format!("argument {path} must be {min} to {max} characters"));
            }
            Ok(())
        }
        Value::Number(_) => {
            let n = value.as_i64().unwrap_or(i64::MAX);
            let min = schema
                .get("minimum")
                .and_then(Value::as_i64)
                .unwrap_or(i64::MIN);
            let max = schema
                .get("maximum")
                .and_then(Value::as_i64)
                .unwrap_or(i64::MAX);
            if n < min || n > max {
                return Err(format!("argument {path} must be between {min} and {max}"));
            }
            Ok(())
        }
        Value::Array(items) => {
            let min = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            let max = schema
                .get("maxItems")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX);
            let n = items.len() as u64;
            if n < min || n > max {
                return Err(format!("argument {path} must have {min} to {max} entries"));
            }
            if let Some(item_schema) = schema.get("items") {
                for (i, item) in items.iter().enumerate() {
                    check(item_schema, item, &format!("{path}[{i}]"))?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn every_schema_is_strict() {
        for t in all() {
            assert_eq!(t.input_schema["type"], "object", "{}", t.name);
            assert_eq!(t.input_schema["additionalProperties"], false, "{}", t.name);
            for (_, p) in t.input_schema["properties"].as_object().unwrap() {
                if p["type"] == "string" && p.get("enum").is_none() {
                    assert!(p["maxLength"].as_u64().is_some(), "{} unbounded", t.name);
                }
            }
        }
    }

    #[test]
    fn validator_covers_the_subset() {
        let schema = json!({
            "type": "object",
            "properties": {
                "argv": {"type": "array", "items": {"type": "string", "maxLength": 3}, "minItems": 1, "maxItems": 2},
                "env": {"type": "object", "additionalProperties": {"type": "string"}, "maxProperties": 1},
                "n": {"type": "integer", "minimum": 1, "maximum": 5},
            },
            "required": ["argv"],
            "additionalProperties": false,
        });
        let c = |v: Value| check_object(&schema, &args(v), "arguments");
        assert!(c(json!({"argv": ["ls"], "env": {"A": "x"}, "n": 5})).is_ok());
        assert!(c(json!({})).is_err());
        assert!(c(json!({"argv": []})).is_err());
        assert!(c(json!({"argv": ["a", "b", "c"]})).is_err());
        assert!(c(json!({"argv": ["toolong"]})).is_err());
        assert!(c(json!({"argv": [1]})).is_err());
        assert!(c(json!({"argv": ["a"], "env": {"A": 1}})).is_err());
        assert!(c(json!({"argv": ["a"], "env": {"A": "x", "B": "y"}})).is_err());
        assert!(c(json!({"argv": ["a"], "n": 0})).is_err());
        assert!(c(json!({"argv": ["a"], "n": 1.5})).is_err());
        assert!(c(json!({"argv": ["a"], "other": 1})).is_err());
    }

    #[test]
    fn messages_do_not_echo_values() {
        let e = validate_args("list_items", &args(json!({"type": "secret-value"}))).unwrap_err();
        assert!(!e.contains("secret-value"), "{e}");
        let e = validate_args("list_items", &args(json!({"hunter2": 1}))).unwrap_err();
        assert!(!e.contains("hunter2"), "{e}");
    }

    #[test]
    fn env_names() {
        for ok in ["A", "_", "TOKEN_2", "A_B_C", &"X".repeat(64)] {
            assert!(env_name_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "a",
            "1A",
            "A-B",
            "A B",
            "ONEPASS_X",
            "É",
            &"X".repeat(65),
        ] {
            assert!(!env_name_ok(bad), "{bad}");
        }
        // The namespace itself without the separator is an ordinary name.
        assert!(env_name_ok("ONEPASS"));
    }

    #[test]
    fn rules_beyond_the_schema() {
        let r = "onepass://V/I/f";
        let run = |v: Value| validate_args("run_with_secrets", &args(v));
        assert!(run(json!({"command": ["ls"], "env": {"A": r}, "files": {"B": r}})).is_ok());
        assert!(run(json!({"command": ["ls"], "env": {"A": r}, "files": {"A": r}})).is_err());
        let e = run(json!({"command": ["ls"], "env": {"lower-secret": r}})).unwrap_err();
        assert!(!e.contains("lower-secret"), "{e}");
        assert!(run(json!({"command": ["ls"], "files": {"ONEPASS_PASSWORD": r}})).is_err());
        assert!(run(json!({"command": ["ls"]})).is_err());
        assert!(run(json!({"command": ["ls"], "env": {}})).is_err());
        let fill = |v: Value| validate_args("fill_template", &args(v));
        assert!(fill(json!({"template_path": "/a", "output_path": "/b"})).is_ok());
        assert!(fill(json!({"template_path": "a", "output_path": "/b"})).is_err());
        assert!(fill(json!({"template_path": "/a", "output_path": "./b"})).is_err());
        let generate = |v: Value| validate_args("generate_password", &args(v));
        assert!(generate(json!({"words": 4})).is_ok());
        assert!(generate(json!({"words": 4, "pin_digits": 6})).is_err());
        assert!(generate(json!({"length": 7})).is_err());
        assert!(generate(json!({"length": 20, "symbols": false})).is_ok());
        assert!(generate(json!({"words": 4, "symbols": true})).is_err());
        assert!(generate(json!({"pin_digits": 6, "symbols": false})).is_err());
    }

    #[test]
    fn item_type_names_are_snake_case() {
        let names = item_types();
        assert_eq!(names.len(), 26);
        assert!(names.contains(&"api_credential".to_owned()));
        assert!(names.contains(&"social_security_number".to_owned()));
        assert!(names.contains(&"login".to_owned()));
    }
}
