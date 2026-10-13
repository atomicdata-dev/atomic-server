//! Writes the rich-text body of a document or meeting from Markdown or plain
//! text: the mirror of the body-to-text reader in the server's MCP module.
//!
//! The body is a loro-prosemirror tree in the Loro map `doc`: a map per node
//! with `nodeName`, `attributes` and `children`, and `LoroText` for text runs,
//! so no editor schema is needed. The editor reads it back like any body typed
//! in the app; attributes left out take the schema's defaults.
//!
//! Supported: headings, paragraphs, fenced code, horizontal rules, block
//! quotes, bullet, numbered and task lists (nested by indentation), and inline
//! **bold**, *italic*, ~~strike~~, `code` and [links](url). Every non-blank
//! line outside a list or code block becomes its own paragraph, which is also
//! how the reader returns a body.

use std::{collections::BTreeMap, sync::LazyLock};

use loro::{
    ExpandType, LoroDoc, LoroList, LoroMap, LoroText, LoroValue, StyleConfig, StyleConfigMap,
};
use regex::Regex;

use crate::errors::AtomicResult;

fn le(e: loro::LoroError) -> crate::errors::AtomicError {
    format!("Loro: {e}").into()
}

/// A mark's value: `{}` for most, `{href}` for a link.
#[derive(Clone, Debug, PartialEq)]
enum Mark {
    Plain,
    Link(String),
}

type Marks = BTreeMap<&'static str, Mark>;

#[derive(Debug)]
struct Run {
    text: String,
    marks: Marks,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ListKind {
    Bullet,
    Ordered,
    Task,
}

impl ListKind {
    fn node_name(self) -> &'static str {
        match self {
            ListKind::Bullet => "bulletList",
            ListKind::Ordered => "orderedList",
            ListKind::Task => "taskList",
        }
    }
}

#[derive(Debug)]
struct Item {
    checked: Option<bool>,
    runs: Vec<Run>,
    children: Vec<Block>,
}

#[derive(Debug)]
enum Block {
    Paragraph(Vec<Run>),
    Heading(u8, Vec<Run>),
    Fenced(Option<String>, String),
    HorizontalRule,
    Blockquote(Vec<Block>),
    List(ListKind, Vec<Item>),
}

const MARK_NAMES: [&str; 5] = ["bold", "italic", "strike", "code", "link"];

static FENCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*```\s*([\w+-]*)\s*$").unwrap());
static HEADING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(#{1,6})\s+(.*?)\s*#*\s*$").unwrap());
static LIST_ITEM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$").unwrap());
static TASK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[([ xX])\]\s+(.*)$").unwrap());
static LINK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[([^\]]+)\]\(([^)\s]+)\)").unwrap());

/// Replaces the body of `doc` with `text`. The caller saves the resource.
pub fn write_document_text(doc: &LoroDoc, text: &str) -> AtomicResult<()> {
    // Marks need their style registered, as the editor does on load.
    let mut styles = StyleConfigMap::new();
    for name in MARK_NAMES {
        let expand = if name == "link" || name == "code" {
            ExpandType::None
        } else {
            ExpandType::After
        };
        styles.insert(name.into(), StyleConfig { expand });
    }
    doc.config_text_style(styles);

    let root = doc.get_map("doc");
    root.insert("nodeName", "doc").map_err(le)?;
    root.insert_container("attributes", LoroMap::new())
        .map_err(le)?;
    // A fresh list replaces whatever body was there.
    let children = root
        .insert_container("children", LoroList::new())
        .map_err(le)?;

    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    for block in parse_blocks(&lines) {
        write_block(&children, &block)?;
    }

    doc.commit();

    Ok(())
}

fn node(parent: &LoroList, name: &str, attributes: &[(&str, LoroValue)]) -> AtomicResult<LoroList> {
    let map = parent.push_container(LoroMap::new()).map_err(le)?;
    map.insert("nodeName", name).map_err(le)?;
    let attrs = map
        .insert_container("attributes", LoroMap::new())
        .map_err(le)?;
    for (key, value) in attributes {
        attrs.insert(key, value.clone()).map_err(le)?;
    }

    map.insert_container("children", LoroList::new())
        .map_err(le)
}

fn write_runs(parent: &LoroList, runs: &[Run]) -> AtomicResult<()> {
    let runs: Vec<&Run> = runs.iter().filter(|r| !r.text.is_empty()).collect();
    if runs.is_empty() {
        return Ok(());
    }

    let text = parent.push_container(LoroText::new()).map_err(le)?;
    let mut at = 0;
    for run in runs {
        let len = run.text.chars().count();
        text.insert(at, &run.text).map_err(le)?;
        for (name, mark) in &run.marks {
            let value: LoroValue = match mark {
                Mark::Plain => LoroValue::Map(std::collections::HashMap::new().into()),
                Mark::Link(href) => LoroValue::Map(
                    std::collections::HashMap::from([(
                        "href".to_string(),
                        LoroValue::from(href.as_str()),
                    )])
                    .into(),
                ),
            };
            text.mark(at..at + len, name, value).map_err(le)?;
        }
        at += len;
    }

    Ok(())
}

fn write_block(parent: &LoroList, block: &Block) -> AtomicResult<()> {
    match block {
        Block::Paragraph(runs) => write_runs(&node(parent, "paragraph", &[])?, runs)?,
        Block::Heading(level, runs) => write_runs(
            &node(
                parent,
                "heading",
                &[("level", LoroValue::from(*level as i64))],
            )?,
            runs,
        )?,
        Block::Fenced(language, text) => {
            let attrs: Vec<(&str, LoroValue)> = language
                .iter()
                .map(|l| ("language", LoroValue::from(l.as_str())))
                .collect();
            let children = node(parent, "codeBlock", &attrs)?;
            if !text.is_empty() {
                children
                    .push_container(LoroText::new())
                    .map_err(le)?
                    .insert(0, text)
                    .map_err(le)?;
            }
        }
        Block::HorizontalRule => {
            node(parent, "horizontalRule", &[])?;
        }
        Block::Blockquote(blocks) => {
            let children = node(parent, "blockquote", &[])?;
            for child in blocks {
                write_block(&children, child)?;
            }
        }
        Block::List(kind, items) => {
            let list = node(parent, kind.node_name(), &[])?;
            for item in items {
                let is_task = *kind == ListKind::Task;
                let attrs: Vec<(&str, LoroValue)> = if is_task {
                    vec![("checked", LoroValue::from(item.checked == Some(true)))]
                } else {
                    vec![]
                };
                let children = node(&list, if is_task { "taskItem" } else { "listItem" }, &attrs)?;
                write_runs(&node(&children, "paragraph", &[])?, &item.runs)?;
                for child in &item.children {
                    write_block(&children, child)?;
                }
            }
        }
    }

    Ok(())
}

fn kind_of(marker: &str, content: &str) -> ListKind {
    if marker.chars().any(|c| c.is_ascii_digit()) {
        ListKind::Ordered
    } else if TASK.is_match(content) {
        ListKind::Task
    } else {
        ListKind::Bullet
    }
}

/// Three or more of one of `- * _`, nothing else (spaces aside).
fn is_rule(line: &str) -> bool {
    let chars: Vec<char> = line.chars().filter(|c| !c.is_whitespace()).collect();

    chars.len() >= 3 && matches!(chars[0], '-' | '*' | '_') && chars.iter().all(|c| *c == chars[0])
}

fn is_quote(line: &str) -> bool {
    line.trim_start().starts_with('>')
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn parse_blocks(lines: &[&str]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        if line.trim().is_empty() {
            i += 1;
            continue;
        }

        if let Some(fence) = FENCE.captures(line) {
            let language = Some(fence[1].to_string()).filter(|l| !l.is_empty());
            let mut body = Vec::new();
            i += 1;
            while i < lines.len() && !FENCE.is_match(lines[i]) {
                body.push(lines[i]);
                i += 1;
            }
            i += 1; // the closing fence
            blocks.push(Block::Fenced(language, body.join("\n")));
            continue;
        }

        if let Some(heading) = HEADING.captures(line) {
            blocks.push(Block::Heading(
                heading[1].len() as u8,
                parse_inline(&heading[2], &Marks::new()),
            ));
            i += 1;
            continue;
        }

        if is_rule(line) {
            blocks.push(Block::HorizontalRule);
            i += 1;
            continue;
        }

        if is_quote(line) {
            let mut quoted: Vec<String> = Vec::new();
            while i < lines.len() && is_quote(lines[i]) {
                let rest = lines[i].trim_start().strip_prefix('>').unwrap_or("");
                quoted.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
                i += 1;
            }
            let refs: Vec<&str> = quoted.iter().map(String::as_str).collect();
            blocks.push(Block::Blockquote(parse_blocks(&refs)));
            continue;
        }

        if LIST_ITEM.is_match(line) {
            let mut list_lines = Vec::new();
            while i < lines.len()
                && !lines[i].trim().is_empty()
                && (LIST_ITEM.is_match(lines[i]) || lines[i].starts_with(char::is_whitespace))
            {
                list_lines.push(lines[i]);
                i += 1;
            }
            blocks.extend(parse_lists(&list_lines));
            continue;
        }

        blocks.push(Block::Paragraph(parse_inline(line.trim(), &Marks::new())));
        i += 1;
    }

    blocks
}

/// Items at the shallowest indent become a list; deeper lines nest in them.
fn parse_lists(lines: &[&str]) -> Vec<Block> {
    let base = lines.iter().map(|l| indent_of(l)).min().unwrap_or(0);
    let mut current: Option<(ListKind, Vec<Item>)> = None;
    let mut nested: Vec<&str> = Vec::new();

    fn flush(current: &mut Option<(ListKind, Vec<Item>)>, nested: &mut Vec<&str>) {
        if let Some((_, items)) = current {
            if !nested.is_empty() {
                if let Some(last) = items.last_mut() {
                    last.children.extend(parse_lists(nested));
                }
            }
        }
        nested.clear();
    }

    let mut finished: Vec<(ListKind, Vec<Item>)> = Vec::new();

    for line in lines {
        let matched = LIST_ITEM.captures(line).filter(|_| indent_of(line) == base);

        if let Some(m) = matched {
            flush(&mut current, &mut nested);
            let (marker, content) = (&m[2], &m[3]);
            let kind = kind_of(marker, content);

            if current.as_ref().is_none_or(|(k, _)| *k != kind) {
                if let Some(done) = current.take() {
                    finished.push(done);
                }
                current = Some((kind, Vec::new()));
            }

            let task = if kind == ListKind::Task {
                TASK.captures(content)
            } else {
                None
            };
            let item = Item {
                checked: task.as_ref().map(|t| &t[1] != " "),
                runs: parse_inline(
                    task.as_ref()
                        .map(|t| t.get(2).unwrap().as_str())
                        .unwrap_or(content),
                    &Marks::new(),
                ),
                children: Vec::new(),
            };
            if let Some((_, items)) = current.as_mut() {
                items.push(item);
            }
        } else {
            nested.push(line);
        }
    }

    flush(&mut current, &mut nested);
    if let Some(done) = current.take() {
        finished.push(done);
    }

    finished
        .into_iter()
        .map(|(k, i)| Block::List(k, i))
        .collect()
}

fn parse_inline(text: &str, marks: &Marks) -> Vec<Run> {
    let chars: Vec<char> = text.chars().collect();
    let mut runs: Vec<Run> = Vec::new();
    let mut literal = String::new();

    fn flush(runs: &mut Vec<Run>, literal: &mut String, marks: &Marks) {
        if !literal.is_empty() {
            runs.push(Run {
                text: std::mem::take(literal),
                marks: marks.clone(),
            });
        }
    }

    let starts_with = |at: usize, pat: &str| -> bool {
        let p: Vec<char> = pat.chars().collect();
        chars.len() >= at + p.len() && chars[at..at + p.len()] == p[..]
    };
    let find = |pat: &str, from: usize| -> Option<usize> {
        let p: Vec<char> = pat.chars().collect();
        (from..chars.len().saturating_sub(p.len() - 1)).find(|&i| chars[i..i + p.len()] == p[..])
    };
    let slice = |a: usize, b: usize| -> String { chars[a..b].iter().collect() };

    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let mut next: Option<usize> = None;

        // `wrapped`: delimiter pairs around inner text, parsed with the extra mark.
        let wrapped =
            |delim: &str, name: &'static str, runs: &mut Vec<Run>, literal: &mut String| {
                let width = delim.chars().count();
                let end = find(delim, i + width)?;
                if end <= i + width {
                    return None;
                }
                flush(runs, literal, marks);
                let mut inner_marks = marks.clone();
                inner_marks.insert(name, Mark::Plain);
                runs.extend(parse_inline(&slice(i + width, end), &inner_marks));

                Some(end + width)
            };

        if c == '\\' && i + 1 < chars.len() {
            literal.push(chars[i + 1]);
            i += 2;
            continue;
        }

        if c == '`' {
            if let Some(end) = find("`", i + 1) {
                if end > i + 1 {
                    flush(&mut runs, &mut literal, marks);
                    let mut m = marks.clone();
                    m.insert("code", Mark::Plain);
                    runs.push(Run {
                        text: slice(i + 1, end),
                        marks: m,
                    });
                    next = Some(end + 1);
                }
            }
        } else if starts_with(i, "**") {
            next = wrapped("**", "bold", &mut runs, &mut literal);
        } else if starts_with(i, "~~") {
            next = wrapped("~~", "strike", &mut runs, &mut literal);
        } else if c == '*' || (c == '_' && (i == 0 || !is_word_char(chars[i - 1]))) {
            next = wrapped(&c.to_string(), "italic", &mut runs, &mut literal);
        } else if c == '[' {
            let rest = slice(i, chars.len());
            if let Some(link) = LINK.captures(&rest) {
                flush(&mut runs, &mut literal, marks);
                let mut m = marks.clone();
                m.insert("link", Mark::Link(link[2].to_string()));
                runs.extend(parse_inline(&link[1], &m));
                next = Some(i + link[0].chars().count());
            }
        }

        match next {
            Some(n) => i = n,
            None => {
                literal.push(c);
                i += 1;
            }
        }
    }

    flush(&mut runs, &mut literal, marks);

    runs
}

/// `snake_case` words must not turn into italics.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(text: &str) -> serde_json::Value {
        let doc = LoroDoc::new();
        write_document_text(&doc, text).unwrap();

        serde_json::to_value(doc.get_map("doc").get_deep_value()).unwrap()
    }

    fn names(node: &serde_json::Value) -> Vec<String> {
        node["children"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["nodeName"].as_str().unwrap_or("text").to_string())
            .collect()
    }

    #[test]
    fn writes_blocks() {
        let value = body("# Title\n\nHello **world**\n\n- one\n- two\n\n```rust\nfn main() {}\n```\n---\n> quoted");

        assert_eq!(value["nodeName"], "doc");
        assert_eq!(
            names(&value),
            [
                "heading",
                "paragraph",
                "bulletList",
                "codeBlock",
                "horizontalRule",
                "blockquote"
            ]
        );
        assert_eq!(value["children"][0]["attributes"]["level"], 1);
        assert_eq!(value["children"][3]["attributes"]["language"], "rust");
    }

    #[test]
    fn task_lists_nest_and_keep_their_state() {
        let value = body("- [x] done\n- [ ] todo\n  - nested");
        let list = &value["children"][0];

        assert_eq!(list["nodeName"], "taskList");
        assert_eq!(list["children"][0]["attributes"]["checked"], true);
        assert_eq!(list["children"][1]["attributes"]["checked"], false);
        assert_eq!(list["children"][1]["children"][1]["nodeName"], "bulletList");
    }

    #[test]
    fn replaces_an_existing_body() {
        let doc = LoroDoc::new();
        write_document_text(&doc, "first\n\nsecond").unwrap();
        write_document_text(&doc, "only").unwrap();
        let value = serde_json::to_value(doc.get_map("doc").get_deep_value()).unwrap();

        assert_eq!(value["children"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn inline_marks_split_runs() {
        let runs = parse_inline("a **b** `c` [d](https://e) snake_case", &Marks::new());
        let texts: Vec<&str> = runs.iter().map(|r| r.text.as_str()).collect();

        assert_eq!(texts, ["a ", "b", " ", "c", " ", "d", " snake_case"]);
        assert_eq!(runs[1].marks.get("bold"), Some(&Mark::Plain));
        assert_eq!(
            runs[5].marks.get("link"),
            Some(&Mark::Link("https://e".into()))
        );
    }
}
