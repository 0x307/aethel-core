//! CORE-03: every public item in `htss` says, in its own doc comment, that it
//! is an in-process simulation and not key protection. The module docs already
//! said so, but rustdoc and IDE hovers show an item's own docs, so a reader who
//! lands on `SecretSharer::split_key_material` never saw the module's warning.
//!
//! The check reads `src/htss.rs` and walks up from each `pub` item to its doc
//! block. Its control runs the same check on a snippet with one undocumented
//! item and requires it to be reported, so the check can be seen failing.

const PHRASE: &str = "In-process simulation, not key protection";

/// Names of `pub` items (not `pub(crate)`) whose doc block lacks [`PHRASE`],
/// plus the number of items checked.
fn missing_phrase(src: &str) -> (Vec<String>, usize) {
    let lines: Vec<&str> = src.lines().collect();
    let mut missing = Vec::new();
    let mut checked = 0;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        let is_item = ["pub fn ", "pub struct ", "pub enum ", "pub const ", "pub type ", "pub trait "]
            .iter()
            .any(|p| t.starts_with(p));
        if !is_item {
            continue;
        }
        // Stop at the test module: its items are not public API.
        if lines[..i].iter().any(|l| l.trim_start().starts_with("#[cfg(test)]")) {
            break;
        }
        checked += 1;
        let name = t.split(['(', '{', ' ', '<', ';', ':']).nth(2).unwrap_or(t).to_string();
        // Walk up past attributes (possibly multi-line) and plain comments.
        let mut j = i;
        let mut in_attr = false;
        let mut doc = String::new();
        while j > 0 {
            j -= 1;
            let u = lines[j].trim();
            if in_attr {
                if u.starts_with("#[") {
                    in_attr = false;
                }
                continue;
            }
            if u.starts_with("///") {
                doc.push_str(u);
                doc.push('\n');
            } else if u.starts_with("#[") {
                continue;
            } else if u.ends_with(")]") {
                in_attr = true;
            } else if u.starts_with("//") {
                continue;
            } else {
                break;
            }
        }
        if !doc.contains(PHRASE) {
            missing.push(name);
        }
    }
    (missing, checked)
}

#[test]
fn every_public_htss_item_says_it_is_a_simulation() {
    let src = include_str!("../src/htss.rs");
    let (missing, checked) = missing_phrase(src);
    // 18 public items in 0.7.6. A parser that finds none would pass vacuously.
    assert!(checked >= 18, "only {checked} public items found; the parser is broken");
    assert!(missing.is_empty(), "htss items without the label: {missing:?}");
}

#[test]
fn control_an_unlabelled_item_is_reported() {
    let snippet = "\
/// Labelled. In-process simulation, not key protection.
#[derive(Clone)]
pub struct Labelled;

/// Has docs, but not the label.
#[deprecated(
    note = \"multi-line attribute\"
)]
pub fn unlabelled() {}

impl Labelled {
    pub fn no_docs_at_all(&self) {}
}
";
    let (missing, checked) = missing_phrase(snippet);
    assert_eq!(checked, 3);
    assert_eq!(missing, vec!["unlabelled".to_string(), "no_docs_at_all".to_string()]);
}
