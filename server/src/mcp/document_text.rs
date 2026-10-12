//! A document or meeting body as Markdown-ish text: the Rust twin of
//! `documentText` in `browser/mcp`, so the hosted and local MCP agree.
//!
//! The body is a loro-prosemirror tree in the Loro map `doc`: every node is a
//! map with `nodeName`, `attributes` and `children`, and a text run is a
//! string. Marks (bold, links) are dropped; block structure is kept.

use serde_json::Value;

pub fn document_text(root: &Value) -> String {
    if root.get("nodeName").is_none() {
        return String::new();
    }
    let mut lines = Vec::new();
    walk(root, &mut lines, "");

    let joined = lines.join("\n");
    let mut collapsed = String::new();
    let mut newlines = 0;
    for c in joined.chars() {
        if c == '\n' {
            newlines += 1;
            if newlines <= 2 {
                collapsed.push(c);
            }
        } else {
            newlines = 0;
            collapsed.push(c);
        }
    }

    collapsed.trim().to_string()
}

fn children(node: &Value) -> &[Value] {
    node.get("children")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn inline_text(node: &Value) -> String {
    children(node)
        .iter()
        .map(|child| match child {
            Value::String(s) => s.clone(),
            other => inline_text(other),
        })
        .collect()
}

fn walk(node: &Value, lines: &mut Vec<String>, indent: &str) {
    match node.get("nodeName").and_then(Value::as_str) {
        Some("heading") => {
            let level = node
                .pointer("/attributes/level")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .clamp(1, 6) as usize;
            lines.push(String::new());
            lines.push(format!("{} {}", "#".repeat(level), inline_text(node)));
            lines.push(String::new());
        }
        Some("paragraph") => lines.push(format!("{indent}{}", inline_text(node))),
        Some("codeBlock") => {
            lines.push("```".into());
            lines.push(inline_text(node));
            lines.push("```".into());
        }
        Some("horizontalRule") => lines.push("---".into()),
        Some("listItem") => list_item(node, lines, indent, ""),
        Some("taskItem") => {
            let checked = node
                .pointer("/attributes/checked")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            list_item(node, lines, indent, if checked { "[x] " } else { "[ ] " })
        }
        _ => {
            for child in children(node) {
                match child {
                    Value::String(s) => lines.push(format!("{indent}{s}")),
                    other => walk(other, lines, indent),
                }
            }
        }
    }
}

/// The first child is the item's own line; later ones (nested lists) indent.
fn list_item(node: &Value, lines: &mut Vec<String>, indent: &str, checkbox: &str) {
    let kids = children(node);
    let first = kids
        .first()
        .map(|first| match first {
            Value::String(s) => s.clone(),
            other => inline_text(other),
        })
        .unwrap_or_default();
    lines.push(format!("{indent}- {checkbox}{first}"));

    for child in kids.iter().skip(1) {
        if !child.is_string() {
            walk(child, lines, &format!("{indent}  "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_headings_lists_and_tasks() {
        let doc = json!({
            "nodeName": "doc",
            "children": [
                {"nodeName": "heading", "attributes": {"level": 2}, "children": ["Plan"]},
                {"nodeName": "paragraph", "children": ["Intro"]},
                {"nodeName": "bulletList", "children": [
                    {"nodeName": "listItem", "children": [
                        {"nodeName": "paragraph", "children": ["one"]},
                        {"nodeName": "bulletList", "children": [
                            {"nodeName": "listItem", "children": [
                                {"nodeName": "paragraph", "children": ["nested"]}
                            ]}
                        ]}
                    ]}
                ]},
                {"nodeName": "taskList", "children": [
                    {"nodeName": "taskItem", "attributes": {"checked": true}, "children": [
                        {"nodeName": "paragraph", "children": ["done"]}
                    ]}
                ]}
            ]
        });

        assert_eq!(
            document_text(&doc),
            "## Plan\n\nIntro\n- one\n  - nested\n- [x] done"
        );
    }

    #[test]
    fn an_empty_body_is_empty() {
        assert_eq!(document_text(&json!({})), "");
    }
}
