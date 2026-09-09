//! Resolves local `#/...` JSON pointer `$ref`s in place.
//!
//! Each `{ "$ref": ... }` node is replaced with the value it points to.
//! Reused (non-cyclic) targets are resolved once and cached so diamond
//! references share a result; a target still being resolved when it is
//! referenced again is a genuine cycle, so that occurrence is left
//! unresolved to avoid recursing forever. Non-local refs (external files,
//! URLs) are left unresolved too, since there is nothing in the document
//! to resolve them against — real-world documents sometimes use these in
//! vendor extensions unrelated to the schemas this crate cares about.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// Resolves every local `$ref` in `document`, returning a new value.
pub fn resolve_refs(document: &Value) -> Value {
    let mut resolver = Resolver {
        root: document,
        resolving: HashSet::new(),
        resolved: HashMap::new(),
    };
    resolver.walk(document)
}

/// A JSON pointer identifying a node, used as the cache/cycle key.
///
/// The TypeScript original keys its `Set`/`Map` on object *identity*;
/// `serde_json` values are cloned rather than shared, so the pointer that
/// reached a node stands in for that identity here.
type NodeKey = String;

struct Resolver<'a> {
    root: &'a Value,
    resolving: HashSet<NodeKey>,
    resolved: HashMap<NodeKey, Value>,
}

impl Resolver<'_> {
    fn resolve_pointer(&self, reference: &str) -> Option<&Value> {
        let trimmed = reference.strip_prefix("#/")?;
        let mut node = self.root;
        for segment in trimmed.split('/') {
            let segment = segment.replace("~1", "/").replace("~0", "~");
            node = node.get(&segment)?;
        }
        Some(node)
    }

    fn walk(&mut self, node: &Value) -> Value {
        match node {
            Value::Array(items) => Value::Array(items.iter().map(|i| self.walk(i)).collect()),
            Value::Object(object) => {
                if let Some(Value::String(reference)) = object.get("$ref") {
                    return self.walk_ref(node, &reference.clone());
                }
                let mut result = serde_json::Map::new();
                for (key, value) in object {
                    result.insert(key.clone(), self.walk(value));
                }
                Value::Object(result)
            }
            other => other.clone(),
        }
    }

    fn walk_ref(&mut self, node: &Value, reference: &str) -> Value {
        if !reference.starts_with("#/") {
            return node.clone();
        }
        let Some(target) = self.resolve_pointer(reference) else {
            return Value::Null;
        };
        if !target.is_object() && !target.is_array() {
            return target.clone();
        }
        let key: NodeKey = reference.to_string();
        if let Some(cached) = self.resolved.get(&key) {
            return cached.clone();
        }
        if self.resolving.contains(&key) {
            return target.clone();
        }

        let target = target.clone();
        self.resolving.insert(key.clone());
        let result = self.walk(&target);
        self.resolving.remove(&key);
        self.resolved.insert(key, result.clone());
        result
    }
}
