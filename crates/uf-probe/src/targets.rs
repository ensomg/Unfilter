//! The embedded test-target set the prober uses to decide whether a strategy
//! actually works (master prompt §5.6 step 2): a few representative domains per
//! category. Shipped as data, overridable by a signed profile update (v1.1).
//!
//! These are only probe destinations for a harmless HTTPS request; no user data
//! is involved (§5.6 step 8).

use serde::{Deserialize, Serialize};

/// Category of a probe target, so a scan can confirm coverage across the kinds
/// of sites users care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetCategory {
    /// Social media.
    Social,
    /// Video / streaming.
    Video,
    /// Messaging (incl. Discord).
    Messaging,
    /// News.
    News,
    /// Generic connectivity check.
    Generic,
}

/// One probe target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Hostname to probe over HTTPS.
    pub host: String,
    /// Its category.
    pub category: TargetCategory,
}

/// A set of probe targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetList {
    /// Schema version, so a signed update can be validated against what the
    /// binary understands.
    pub version: u32,
    /// The targets.
    pub targets: Vec<Target>,
}

impl TargetList {
    /// The built-in default set. Representative public hosts per category; the
    /// prober fetches a harmless HTTPS resource and checks for a real response
    /// vs. a block page / RST / timeout.
    pub fn builtin() -> TargetList {
        fn t(host: &str, category: TargetCategory) -> Target {
            Target {
                host: host.to_string(),
                category,
            }
        }
        TargetList {
            version: 1,
            targets: vec![
                t("www.google.com", TargetCategory::Generic),
                t("www.cloudflare.com", TargetCategory::Generic),
                t("x.com", TargetCategory::Social),
                t("www.instagram.com", TargetCategory::Social),
                t("www.youtube.com", TargetCategory::Video),
                t("www.netflix.com", TargetCategory::Video),
                t("discord.com", TargetCategory::Messaging),
                t("web.whatsapp.com", TargetCategory::Messaging),
                t("www.bbc.com", TargetCategory::News),
                t("www.dw.com", TargetCategory::News),
            ],
        }
    }

    /// Hosts in a given category.
    pub fn in_category(&self, category: TargetCategory) -> impl Iterator<Item = &str> {
        self.targets
            .iter()
            .filter(move |t| t.category == category)
            .map(|t| t.host.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_covers_every_category() {
        let list = TargetList::builtin();
        for cat in [
            TargetCategory::Social,
            TargetCategory::Video,
            TargetCategory::Messaging,
            TargetCategory::News,
            TargetCategory::Generic,
        ] {
            assert!(list.in_category(cat).next().is_some(), "missing {cat:?}");
        }
    }

    #[test]
    fn target_list_roundtrips_json() {
        let list = TargetList::builtin();
        let json = serde_json::to_string(&list).unwrap();
        let back: TargetList = serde_json::from_str(&json).unwrap();
        assert_eq!(list, back);
    }
}
