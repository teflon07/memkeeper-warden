//! The capability vocabulary: classes and the parsed `(class, scope)` pair a
//! skill declares in its manifest.

/// One of the capability classes warden understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityClass {
    /// Read files.
    FsRead,
    /// Write/create files.
    FsWrite,
    /// Outbound network to a host.
    Net,
    /// Spawn a subprocess.
    Exec,
    /// Read memories from memkeeper.
    MemoryRead,
    /// Write memories to memkeeper.
    MemoryWrite,
    /// Access a named secret.
    Secrets,
}

impl CapabilityClass {
    /// Parse the leading token (`fs:read`, `net`, ...) into a class.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "fs:read" => Self::FsRead,
            "fs:write" => Self::FsWrite,
            "net" => Self::Net,
            "exec" => Self::Exec,
            "memory:read" => Self::MemoryRead,
            "memory:write" => Self::MemoryWrite,
            "secrets" => Self::Secrets,
            _ => return None,
        })
    }

    /// Stable wire/display token for the class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs:read",
            Self::FsWrite => "fs:write",
            Self::Net => "net",
            Self::Exec => "exec",
            Self::MemoryRead => "memory:read",
            Self::MemoryWrite => "memory:write",
            Self::Secrets => "secrets",
        }
    }
}

/// A declared grant request: a class plus its raw scope expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// The capability class.
    pub class: CapabilityClass,
    /// Raw scope string, interpreted per class by `scope::matches`.
    pub scope: String,
}

/// Why a capability line could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Leading token is not a known class.
    UnknownClass(String),
    /// No scope followed the class token.
    MissingScope,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownClass(t) => write!(f, "unknown capability class: {t}"),
            Self::MissingScope => write!(f, "capability is missing a scope"),
        }
    }
}

impl std::error::Error for ParseError {}

impl Capability {
    /// Parse one declaration line: `<class> <scope...>`.
    ///
    /// # Errors
    /// Returns [`ParseError`] if the class is unknown or the scope is empty.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let line = line.trim();
        let (token, scope) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let class = CapabilityClass::parse(token)
            .ok_or_else(|| ParseError::UnknownClass(token.to_string()))?;
        let scope = scope.trim();
        if scope.is_empty() {
            return Err(ParseError::MissingScope);
        }
        Ok(Self {
            class,
            scope: scope.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_class_and_scope() {
        let cap = Capability::parse("fs:read ~/projects/app").unwrap();
        assert_eq!(cap.class, CapabilityClass::FsRead);
        assert_eq!(cap.scope, "~/projects/app");
    }

    #[test]
    fn parses_each_known_class() {
        let cases = [
            ("fs:write /tmp/out", CapabilityClass::FsWrite),
            ("net api.anthropic.com", CapabilityClass::Net),
            ("exec git", CapabilityClass::Exec),
            ("memory:read silo=notes", CapabilityClass::MemoryRead),
            ("memory:write silo=notes", CapabilityClass::MemoryWrite),
            ("secrets OPENAI_API_KEY", CapabilityClass::Secrets),
        ];
        for (line, class) in cases {
            assert_eq!(
                Capability::parse(line).unwrap().class,
                class,
                "line: {line}"
            );
        }
    }

    #[test]
    fn rejects_unknown_class() {
        assert!(Capability::parse("teleport somewhere").is_err());
    }

    #[test]
    fn rejects_missing_scope() {
        assert!(Capability::parse("fs:read").is_err());
        assert!(Capability::parse("fs:read    ").is_err());
    }
}
