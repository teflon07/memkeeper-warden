//! A concrete attempted action the broker evaluates against granted capabilities.

use crate::capability::CapabilityClass;

/// One concrete action: a class and the single target it acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The capability class being exercised.
    pub class: CapabilityClass,
    /// The concrete target: a path, host, binary, `silo=`/`space=` value, or secret name.
    pub target: String,
}

impl Request {
    /// Construct a request from a class and target string.
    #[must_use]
    pub fn new(class: CapabilityClass, target: impl Into<String>) -> Self {
        Self {
            class,
            target: target.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityClass;

    #[test]
    fn holds_class_and_target() {
        let req = Request::new(CapabilityClass::FsRead, "/etc/hosts");
        assert_eq!(req.class, CapabilityClass::FsRead);
        assert_eq!(req.target, "/etc/hosts");
    }
}
