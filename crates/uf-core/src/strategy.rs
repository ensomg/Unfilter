//! Strategy abstraction: a named, ordered list of desync actions, plus the
//! trait the engine drives and the pre-allocated [`Emitter`] a strategy writes
//! its output packets into.

use crate::action::DesyncAction;
use crate::flow::FlowKey;
use crate::io::{MAX_PACKET, PacketMeta};
use serde::{Deserialize, Serialize};

/// Stable identifier of a strategy within the active set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StrategyId(pub u16);

/// A strategy defined entirely as data: a name and the actions to apply, in
/// order. Loaded from config; this is the schema the prober scores and the UI
/// reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategySpec {
    /// Human-readable name shown in the UI / logs (e.g. "split+fake_badsum").
    pub name: String,
    /// Actions applied in order to a flow's opening handshake.
    pub actions: Vec<DesyncAction>,
}

/// What the engine should do with the packet it handed to a strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Re-inject the original packet unchanged (no action taken).
    Pass,
    /// Drop the original packet; it must not be injected.
    Drop,
    /// The strategy wrote one or more replacement packets into the [`Emitter`];
    /// inject those and drop the original.
    Emitted,
}

/// One packet a strategy wants injected: its bytes and the metadata to inject
/// it with.
pub struct OutPacket {
    buf: [u8; MAX_PACKET],
    len: usize,
    meta: PacketMeta,
}

impl OutPacket {
    const fn empty() -> Self {
        OutPacket {
            buf: [0u8; MAX_PACKET],
            len: 0,
            meta: PacketMeta {
                direction: crate::io::Direction::Outbound,
                if_index: 0,
                sub_if_index: 0,
                loopback: false,
                impostor: false,
                checksums_valid: false,
                captured_at_nanos: 0,
            },
        }
    }

    /// The packet's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The metadata to inject with.
    pub fn meta(&self) -> &PacketMeta {
        &self.meta
    }
}

/// Fixed number of output slots per input packet. Enough for the richest
/// composition we support (split into several parts + a fake + reordering).
pub const MAX_EMIT: usize = 8;

/// A strategy's output buffer, pre-allocated so [`emit`](Emitter::emit) never
/// allocates on the hot path. One lives per engine thread and is reset between
/// packets.
pub struct Emitter {
    slots: [OutPacket; MAX_EMIT],
    count: usize,
}

impl Default for Emitter {
    fn default() -> Self {
        Emitter::new()
    }
}

impl Emitter {
    /// A fresh, empty emitter with all slots pre-allocated.
    pub fn new() -> Self {
        Emitter {
            slots: core::array::from_fn(|_| OutPacket::empty()),
            count: 0,
        }
    }

    /// Discard any queued output. Called before handing the emitter to a
    /// strategy for a new packet.
    pub fn reset(&mut self) {
        self.count = 0;
    }

    /// Queue a packet for injection. Returns `false` (and queues nothing) if the
    /// data does not fit or all slots are used — the caller then falls back to
    /// pass-through.
    pub fn emit(&mut self, data: &[u8], meta: PacketMeta) -> bool {
        if self.count >= MAX_EMIT || data.len() > MAX_PACKET {
            return false;
        }
        let slot = &mut self.slots[self.count];
        slot.buf[..data.len()].copy_from_slice(data);
        slot.len = data.len();
        slot.meta = meta;
        self.count += 1;
        true
    }

    /// The packets queued so far, in injection order.
    pub fn packets(&self) -> &[OutPacket] {
        &self.slots[..self.count]
    }

    /// How many packets are queued.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Context a strategy sees for the flow it is acting on.
pub struct FlowCtx<'a> {
    /// The flow's 5-tuple.
    pub key: &'a FlowKey,
    /// Metadata of the packet being processed.
    pub meta: &'a PacketMeta,
    /// Index of the payload-bearing packet within the flow (0 = first).
    pub payload_index: u32,
}

/// A bypass strategy. Implementations are built from a [`StrategySpec`] in
/// phase 2; the engine only ever sees this trait.
pub trait Strategy {
    /// This strategy's identifier.
    fn id(&self) -> StrategyId;

    /// Apply the strategy to one packet of a flow. Write any replacement
    /// packets to `out` and return [`Verdict::Emitted`]; or return
    /// [`Verdict::Pass`] / [`Verdict::Drop`] to leave `out` untouched.
    fn apply(&self, ctx: &FlowCtx<'_>, packet: &[u8], out: &mut Emitter) -> Verdict;
}
