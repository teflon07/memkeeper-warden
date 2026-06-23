//! Parse the optional `capabilities:` list from a SKILL.md YAML frontmatter
//! block. Hand-rolled and intentionally minimal: a `capabilities:` key followed
//! by `  - <capability>` list items, terminated by the next non-indented line
//! or the closing `---`.

use crate::capability::{Capability, ParseError};

/// Extract declared capabilities from a SKILL.md document.
///
/// Returns an empty vec when there is no frontmatter or no `capabilities:` block.
///
/// # Errors
/// Returns [`ParseError`] if a listed capability line cannot be parsed.
pub fn parse_capabilities(doc: &str) -> Result<Vec<Capability>, ParseError> {
    let Some(frontmatter) = extract_frontmatter(doc) else {
        return Ok(Vec::new());
    };
    let mut caps = Vec::new();
    let mut in_block = false;
    for line in frontmatter.lines() {
        if !in_block {
            if line.trim_end() == "capabilities:" {
                in_block = true;
            }
            continue;
        }
        // List items are indented "  - ...". Any non-indented, non-list line ends the block.
        let trimmed = line.trim_start();
        if let Some(item) = trimmed.strip_prefix("- ") {
            caps.push(Capability::parse(item.trim())?);
        } else if line.starts_with(char::is_whitespace) || trimmed.is_empty() {
            // Blank or indented continuation that is not a list item: skip.
            if trimmed.is_empty() {
                continue;
            }
            break;
        } else {
            break;
        }
    }
    Ok(caps)
}

/// Extract the `name:` field from a SKILL.md frontmatter block, if present.
#[must_use]
pub fn parse_name(doc: &str) -> Option<String> {
    let frontmatter = extract_frontmatter(doc)?;
    for line in frontmatter.lines() {
        if let Some(rest) = line.trim_end().strip_prefix("name:") {
            let v = rest.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Return the text between the opening `---` and the next `---`, if present.
fn extract_frontmatter(doc: &str) -> Option<&str> {
    let rest = doc
        .strip_prefix("---\n")
        .or_else(|| doc.strip_prefix("---\r\n"))?;
    let end = rest.find("\n---")?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityClass;

    const SKILL: &str = "---\nname: morning-note\ndescription: Draft the note\ncapabilities:\n  - memory:read silo=notes\n  - fs:read ~/projects/app\n  - net api.example.com\n---\n\n# Morning Note\n\nBody text here.\n";

    #[test]
    fn extracts_declared_capabilities() {
        let caps = parse_capabilities(SKILL).unwrap();
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0].class, CapabilityClass::MemoryRead);
        assert_eq!(caps[1].class, CapabilityClass::FsRead);
        assert_eq!(caps[2].class, CapabilityClass::Net);
    }

    #[test]
    fn no_block_yields_empty() {
        let md = "---\nname: x\ndescription: y\n---\nbody\n";
        assert!(parse_capabilities(md).unwrap().is_empty());
    }

    #[test]
    fn no_frontmatter_yields_empty() {
        assert!(parse_capabilities("# just a heading\n").unwrap().is_empty());
    }

    #[test]
    fn malformed_capability_line_is_error() {
        let md = "---\ncapabilities:\n  - teleport somewhere\n---\n";
        assert!(parse_capabilities(md).is_err());
    }

    #[test]
    fn parses_skill_name() {
        assert_eq!(parse_name(SKILL).as_deref(), Some("morning-note"));
    }

    #[test]
    fn no_name_yields_none() {
        let md = "---\ndescription: y\n---\nbody\n";
        assert!(parse_name(md).is_none());
    }

    #[test]
    fn no_frontmatter_name_is_none() {
        assert!(parse_name("# heading\n").is_none());
    }
}
