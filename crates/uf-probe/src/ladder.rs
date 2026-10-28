//! The candidate ladder: the ordered list of strategies the prober tries,
//! cheapest/lightest first, so the first working one is found fast (master
//! prompt §5.6 step 4).
//!
//! Each candidate is a [`StrategySpec`] (data defined in `uf-core`) paired with a
//! coarse cost. This module only *orders and labels* strategies; it never builds
//! packets — turning a `StrategySpec` into bytes is the engine's job (Faz 2).

use uf_core::action::{DesyncAction, FakeKind, Fooling, SplitPos, TtlSpec};
use uf_core::strategy::StrategySpec;

/// Coarse cost of a candidate, used only to order the ladder. Cheaper first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cost {
    /// No packet rewriting at all (rely on the DoH/DoT fix only).
    DnsOnly,
    /// A single cheap transformation.
    Light,
    /// Two composed transformations.
    Medium,
    /// Injects an extra packet.
    Heavy,
    /// Several composed techniques.
    Max,
}

/// A ladder entry: a strategy and its cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The strategy, as config data.
    pub spec: StrategySpec,
    /// Its cost bucket (ladder order).
    pub cost: Cost,
}

fn spec(name: &str, actions: Vec<DesyncAction>) -> StrategySpec {
    StrategySpec {
        name: name.to_string(),
        actions,
    }
}

/// The default ladder, ordered cheapest-first. The prober tries these in order,
/// confirms the first that works against the target set, then keeps the best
/// plus backups (scored by [`ScoreBoard`](crate::score::ScoreBoard)).
pub fn default_ladder() -> Vec<Candidate> {
    vec![
        // 0: nothing but the DNS fix (for DNS-only blocks).
        Candidate {
            spec: spec("dns_only", vec![]),
            cost: Cost::DnsOnly,
        },
        // 1: split the ClientHello at the SNI.
        Candidate {
            spec: spec(
                "split_sni",
                vec![DesyncAction::Split {
                    at: SplitPos::SniMid,
                }],
            ),
            cost: Cost::Light,
        },
        // 2: split + reverse order of the pieces.
        Candidate {
            spec: spec(
                "split_disorder",
                vec![
                    DesyncAction::Split {
                        at: SplitPos::SniMid,
                    },
                    DesyncAction::Disorder,
                ],
            ),
            cost: Cost::Medium,
        },
        // 3: fake packet with an auto TTL (dies before the server).
        Candidate {
            spec: spec(
                "fake_ttl",
                vec![DesyncAction::Fake {
                    kind: FakeKind::TlsClientHelloFakeSni,
                    ttl: TtlSpec::Auto { delta: -1 },
                    fooling: Fooling::NONE,
                }],
            ),
            cost: Cost::Heavy,
        },
        // 4: fake packet invalidated by a bad checksum.
        Candidate {
            spec: spec(
                "fake_badsum",
                vec![DesyncAction::Fake {
                    kind: FakeKind::TlsClientHelloFakeSni,
                    ttl: TtlSpec::Fixed(4),
                    fooling: Fooling::BADSUM,
                }],
            ),
            cost: Cost::Heavy,
        },
        // 5: the combination — split, disorder, and a fooling fake.
        Candidate {
            spec: spec(
                "split_disorder_fake",
                vec![
                    DesyncAction::Split {
                        at: SplitPos::SniMid,
                    },
                    DesyncAction::Disorder,
                    DesyncAction::Fake {
                        kind: FakeKind::TlsClientHelloFakeSni,
                        ttl: TtlSpec::Auto { delta: -1 },
                        fooling: Fooling::BADSUM | Fooling::BADSEQ,
                    },
                ],
            ),
            cost: Cost::Max,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_is_cost_ordered() {
        let ladder = default_ladder();
        assert!(ladder.len() >= 5);
        for pair in ladder.windows(2) {
            assert!(
                pair[0].cost <= pair[1].cost,
                "ladder not cheapest-first at {:?} -> {:?}",
                pair[0].spec.name,
                pair[1].spec.name
            );
        }
    }

    #[test]
    fn first_candidate_is_dns_only() {
        let ladder = default_ladder();
        assert_eq!(ladder[0].cost, Cost::DnsOnly);
        assert!(ladder[0].spec.actions.is_empty());
    }

    #[test]
    fn specs_serialise_as_config() {
        // The ladder is data: it must round-trip through the config format.
        let ladder = default_ladder();
        for c in &ladder {
            let json = serde_json::to_string(&c.spec).unwrap();
            let back: StrategySpec = serde_json::from_str(&json).unwrap();
            assert_eq!(c.spec, back);
        }
    }
}
