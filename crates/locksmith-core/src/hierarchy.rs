//! Hierarchical resource ids.
//!
//! Resources containing `/` form a tree: `workspace/frontend/button.rs`
//! has ancestors `workspace` and `workspace/frontend`. Locking an ancestor
//! constrains descendants according to the lock mode; see the manager for
//! the compatibility rules.

/// Normalize a resource id: trim duplicate and trailing slashes so that
/// `workspace/` and `workspace` address the same resource.
pub fn normalize(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    let mut prev_slash = false;
    for c in id.chars() {
        if c == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push(c);
    }
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// All strict ancestors of a path-like resource, shortest first.
///
/// ```
/// use locksmith_core::hierarchy::ancestors;
/// assert_eq!(ancestors("a/b/c"), vec!["a".to_string(), "a/b".to_string()]);
/// assert!(ancestors("gpu:0").is_empty());
/// ```
pub fn ancestors(id: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = id.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'/' {
            let prefix = &id[..i];
            if !prefix.is_empty() {
                out.push(prefix.to_string());
            }
        }
    }
    out
}

/// True if `ancestor` is a strict ancestor of `id`.
pub fn is_ancestor(ancestor: &str, id: &str) -> bool {
    id.len() > ancestor.len() && id.starts_with(ancestor) && id.as_bytes()[ancestor.len()] == b'/'
}

/// True if the two resources are the same or one contains the other.
pub fn related(a: &str, b: &str) -> bool {
    a == b || is_ancestor(a, b) || is_ancestor(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestor_chain() {
        assert_eq!(
            ancestors("workspace/frontend/components/button.rs"),
            vec![
                "workspace".to_string(),
                "workspace/frontend".to_string(),
                "workspace/frontend/components".to_string()
            ]
        );
    }

    #[test]
    fn non_hierarchical_ids_have_no_ancestors() {
        assert!(ancestors("gpu:0").is_empty());
        assert!(ancestors("workspace").is_empty());
    }

    #[test]
    fn leading_slash() {
        assert_eq!(ancestors("/src/main.rs"), vec!["/src".to_string()]);
        assert!(is_ancestor("/src", "/src/main.rs"));
        assert!(!is_ancestor("/src", "/srcx/main.rs"));
    }

    #[test]
    fn normalize_collapses_slashes() {
        assert_eq!(normalize("a//b/"), "a/b");
        assert_eq!(normalize("/a/b/"), "/a/b");
        assert_eq!(normalize("/"), "/");
    }

    #[test]
    fn relatedness() {
        assert!(related("a", "a/b"));
        assert!(related("a/b", "a"));
        assert!(related("a", "a"));
        assert!(!related("a", "ab"));
        assert!(!related("a/b", "a/c"));
    }
}
