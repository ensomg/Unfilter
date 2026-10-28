//! Packet I/O abstraction.
//!
//! The engine never talks to WinDivert (or any OS facility) directly; it drives
//! a [`PacketIO`] implementation. A platform adapter lives in a separate crate
//! (e.g. `uf-capture`) and is the only place that touches the kernel.
//!
//! Buffers are owned by a [`BufferPool`] that is sized once at start-up. On the
//! hot path only small indices move between threads, never packet bytes.

use crate::error::{Error, Result};

/// Maximum size of a single captured packet we are willing to process.
///
/// Covers a standard 1500-byte MTU plus headroom for a WinDivert re-inject of a
/// segment we grew slightly. Packets larger than this are passed through
/// untouched rather than parsed.
pub const MAX_PACKET: usize = 2048;

/// Direction of travel relative to the local host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Leaving this host (the only direction v1 rewrites).
    Outbound,
    /// Arriving at this host (observed for RST/verify logic).
    Inbound,
}

/// Metadata that travels alongside a packet's bytes.
///
/// Mirrors the fields a capture backend needs to re-inject a packet to the right
/// place. Kept `Copy` and allocation-free so it can ride a lock-free queue.
#[derive(Debug, Clone, Copy)]
pub struct PacketMeta {
    /// Outbound vs inbound.
    pub direction: Direction,
    /// OS interface index the packet was captured on (for correct re-inject).
    pub if_index: u32,
    /// Sub-interface index (WinDivert `SubIfIdx`).
    pub sub_if_index: u32,
    /// Packet is on the loopback interface.
    pub loopback: bool,
    /// Packet was injected by us or another program (avoid re-processing ours).
    pub impostor: bool,
    /// Packet is IPv6 (affects header parsing and re-inject address flags).
    pub ipv6: bool,
    /// IP and TCP/UDP checksums are known-valid as captured. After we mutate a
    /// packet we clear this so the backend recomputes them before injection.
    pub checksums_valid: bool,
    /// Monotonic capture timestamp in nanoseconds, used only for the latency
    /// histogram. Source is the backend's clock; never compared across hosts.
    pub captured_at_nanos: u64,
}

impl PacketMeta {
    /// A plain outbound metadata value with valid checksums and no timestamp.
    pub fn outbound(if_index: u32) -> Self {
        PacketMeta {
            direction: Direction::Outbound,
            if_index,
            sub_if_index: 0,
            loopback: false,
            impostor: false,
            ipv6: false,
            checksums_valid: true,
            captured_at_nanos: 0,
        }
    }
}

/// A single packet buffer: a fixed inline byte array plus a logical length.
///
/// Fixed-size so buffers can live in a contiguous pool with no per-packet
/// allocation. The unused tail is not zeroed on reuse; only `data()[..len]` is
/// ever read.
pub struct PacketBuf {
    data: [u8; MAX_PACKET],
    len: usize,
}

impl Default for PacketBuf {
    fn default() -> Self {
        PacketBuf::new()
    }
}

impl PacketBuf {
    /// A new, empty buffer.
    pub const fn new() -> Self {
        PacketBuf {
            data: [0u8; MAX_PACKET],
            len: 0,
        }
    }

    /// Number of valid bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The valid bytes as an immutable slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// The valid bytes as a mutable slice (for in-place edits that keep length).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Replace the contents with `src`. Returns [`Error::Capacity`] if `src`
    /// does not fit in [`MAX_PACKET`].
    pub fn set(&mut self, src: &[u8]) -> Result<()> {
        if src.len() > MAX_PACKET {
            return Err(Error::Capacity);
        }
        self.data[..src.len()].copy_from_slice(src);
        self.len = src.len();
        Ok(())
    }

    /// Clear the logical length without touching the backing bytes.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// The full backing storage as a mutable slice, for a capture backend to
    /// write a freshly received packet into before [`set_len`](Self::set_len).
    /// The bytes are always initialised (the array is zero-filled), so this is
    /// safe.
    pub fn backing_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Set the logical length after writing into [`backing_mut`](Self::backing_mut).
    ///
    /// # Panics
    /// If `len` exceeds [`MAX_PACKET`].
    pub fn set_len(&mut self, len: usize) {
        assert!(len <= MAX_PACKET, "length {len} exceeds MAX_PACKET");
        self.len = len;
    }
}

/// A fixed-capacity pool of packet buffers, allocated once at start-up.
///
/// Acquire hands out an index into the pool; release returns it. The hot path
/// moves these indices between threads instead of copying packet data. Running
/// out of buffers is a non-fatal [`Error::Capacity`]: the caller passes the
/// packet through unmodified.
pub struct BufferPool {
    bufs: Vec<PacketBuf>,
    free: Vec<u32>,
}

/// Index of a buffer inside a [`BufferPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufId(pub u32);

impl BufferPool {
    /// Allocate a pool of `capacity` buffers up front. All memory used by the
    /// pool is reserved here; the hot path never grows it.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut bufs = Vec::with_capacity(capacity);
        let mut free = Vec::with_capacity(capacity);
        for i in 0..capacity {
            bufs.push(PacketBuf::new());
            free.push((capacity - 1 - i) as u32);
        }
        BufferPool { bufs, free }
    }

    /// Total number of buffers in the pool.
    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }

    /// Number of buffers currently available.
    pub fn available(&self) -> usize {
        self.free.len()
    }

    /// Take a free buffer index, or [`Error::Capacity`] if the pool is empty.
    pub fn acquire(&mut self) -> Result<BufId> {
        self.free.pop().map(BufId).ok_or(Error::Capacity)
    }

    /// Return a buffer to the pool. The buffer's length is reset to zero.
    pub fn release(&mut self, id: BufId) {
        self.bufs[id.0 as usize].clear();
        self.free.push(id.0);
    }

    /// Borrow a buffer immutably.
    pub fn get(&self, id: BufId) -> &PacketBuf {
        &self.bufs[id.0 as usize]
    }

    /// Borrow a buffer mutably.
    pub fn get_mut(&mut self, id: BufId) -> &mut PacketBuf {
        &mut self.bufs[id.0 as usize]
    }
}

/// The boundary between the engine and the operating system.
///
/// Implementations block in [`recv`](PacketIO::recv) until a packet matching the
/// backend's capture filter arrives, then the engine decides whether to re-inject
/// it unchanged or emit a rewritten sequence via [`send`](PacketIO::send).
///
/// The contract that guarantees fail-open: if the engine returns early or panics,
/// the backend's `Drop` must tear down capture so traffic flows normally.
pub trait PacketIO {
    /// Block until the next packet is available, copy it into `buf`, and return
    /// its metadata. [`Error::Shutdown`] means the loop should end.
    fn recv(&mut self, buf: &mut PacketBuf) -> Result<PacketMeta>;

    /// Inject one packet described by `meta`. If `meta.checksums_valid` is
    /// false the backend recomputes IP/TCP/UDP checksums first.
    fn send(&mut self, pkt: &[u8], meta: &PacketMeta) -> Result<()>;

    /// Inject a batch of packets in order. The default sends them one by one;
    /// backends that support vectored injection override this.
    fn send_batch(&mut self, pkts: &[(&[u8], PacketMeta)]) -> Result<()> {
        for (pkt, meta) in pkts {
            self.send(pkt, meta)?;
        }
        Ok(())
    }

    /// Tear down capture and unblock any in-flight [`recv`](PacketIO::recv).
    /// Idempotent.
    fn shutdown(&mut self);
}
