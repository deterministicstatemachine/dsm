// SPDX-License-Identifier: MIT OR Apache-2.0
//! Frames over any link. A host sends LE32-length-prefixed protobuf request frames; each is streamed
//! through the Secure Gateway in slot-sized parts (the monitor assembles the frame, decodes the op,
//! applies the §2 measurement seal and serves it through the anchor), and the framed response is
//! streamed back the same way. Fixed buffers (no heap): one slot-sized part in each direction.
//!
//! A frame larger than any frame, or a part the Secure side refuses, is answered with an empty
//! frame (the host refuses it); the bytes of the refused frame are read and dropped so the stream
//! stays in step. The two transports, USB and Bluetooth, serve one frame at a time between them:
//! the gateway assembles one request, so a frame is taken whole from one link, its answer sent,
//! before the other link's frame is read.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

use crate::gateway::{self, Crossing, SG_FRAME_MAX_LEN, SG_MORE, SG_OK, SG_SLOT_MAX_LEN};

/// Whose turn it is at the gateway: held from a frame's first byte to its answer's last.
static TURN: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());

/// A host link: bytes in, bytes out, and the moment the host is no longer there.
pub trait Link {
    /// At least one byte, or the host is gone. A host that is there but silent is waited for.
    async fn read(&mut self, into: &mut [u8]) -> Result<usize, HostGone>;
    /// Every byte, or the host is gone.
    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), HostGone>;
}

/// The host left (its port closed, its connection dropped) or opened a new conversation: whatever
/// frame was in progress is abandoned, and the next byte starts a new one.
#[derive(Debug, Clone, Copy)]
pub struct HostGone;

/// Bytes read from the link and not yet taken into a frame.
const CHUNK: usize = 64;

/// The frame being read: its header, how much of it has gone to the Secure side, and whether the
/// Secure side refused it (its remaining bytes are then dropped).
pub struct FrameServer {
    chunk: [u8; CHUNK],
    chunk_len: usize,
    chunk_pos: usize,
    header: [u8; 4],
    header_len: usize,
    part: [u8; SG_SLOT_MAX_LEN],
    part_len: usize,
    resp: [u8; SG_SLOT_MAX_LEN],
    total: usize,
    forwarded: usize,
    refused: u8,
}

/// What one byte did to the frame in progress.
enum Step {
    /// The frame wants more bytes.
    More,
    /// The frame is complete and its answer has gone out.
    Done,
}

impl FrameServer {
    pub const fn new() -> Self {
        Self {
            chunk: [0; CHUNK],
            chunk_len: 0,
            chunk_pos: 0,
            header: [0; 4],
            header_len: 0,
            part: [0; SG_SLOT_MAX_LEN],
            part_len: 0,
            resp: [0; SG_SLOT_MAX_LEN],
            total: 0,
            forwarded: 0,
            refused: 0,
        }
    }

    /// Serve one host until it is gone: every frame it sends, answered on the same link.
    pub async fn serve<L: Link>(&mut self, link: &mut L) -> HostGone {
        self.reset();
        loop {
            if let Err(gone) = self.serve_frame(link).await {
                self.reset();
                return gone;
            }
        }
    }

    fn reset(&mut self) {
        self.chunk_len = 0;
        self.chunk_pos = 0;
        self.header_len = 0;
        self.total = 0;
        self.forwarded = 0;
        self.part_len = 0;
        self.refused = 0;
    }

    /// The next byte from the host, read from the link when the last chunk is used up.
    async fn next_byte<L: Link>(&mut self, link: &mut L) -> Result<u8, HostGone> {
        if self.chunk_pos == self.chunk_len {
            self.chunk_len = link.read(&mut self.chunk).await?;
            self.chunk_pos = 0;
        }
        let byte = self.chunk[self.chunk_pos];
        self.chunk_pos += 1;
        Ok(byte)
    }

    /// One frame: from its first header byte, holding the gateway's turn from then until its
    /// answer has gone out. An idle link holds nothing up: the turn is taken once a byte is there.
    async fn serve_frame<L: Link>(&mut self, link: &mut L) -> Result<(), HostGone> {
        let first = self.next_byte(link).await?;
        let turn = TURN.lock().await;
        let mut step = self.push(link, first).await?;
        while let Step::More = step {
            let byte = self.next_byte(link).await?;
            step = self.push(link, byte).await?;
        }
        drop(turn);
        Ok(())
    }

    /// Feed one byte into the frame in progress: header bytes, then the frame's bytes in parts,
    /// each complete part crossing the gateway, the answer written when the last one does.
    async fn push<L: Link>(&mut self, link: &mut L, byte: u8) -> Result<Step, HostGone> {
        if self.header_len < 4 {
            self.header[self.header_len] = byte;
            self.header_len += 1;
            if self.header_len < 4 {
                return Ok(Step::More);
            }
            self.total = u32::from_le_bytes(self.header) as usize;
            self.forwarded = 0;
            self.part_len = 0;
            self.refused = u8::from(self.total > SG_FRAME_MAX_LEN);
            if self.total > 0 {
                return Ok(Step::More);
            }
        } else {
            if self.refused == 0 {
                self.part[self.part_len] = byte;
            }
            self.part_len += 1;
            if self.part_len < SG_SLOT_MAX_LEN && self.forwarded + self.part_len < self.total {
                return Ok(Step::More);
            }
        }
        // A part is complete (a full slot, or the frame's last bytes): forward it.
        if self.refused == 0 {
            let crossing = gateway::request_part(
                self.forwarded,
                self.total,
                &self.part[..self.part_len],
                &mut self.resp,
            );
            match crossing.status {
                SG_MORE => {}
                SG_OK => self.write_response(link, &crossing).await?,
                _refused => self.refused = 1,
            }
        }
        self.forwarded += self.part_len;
        self.part_len = 0;
        if self.forwarded < self.total {
            return Ok(Step::More);
        }
        if self.refused != 0 {
            link.write_all(&0u32.to_le_bytes()).await?;
        }
        self.header_len = 0;
        Ok(Step::Done)
    }

    /// Write a response frame: its length, its first part, then each further part the Secure side
    /// serves. A crossing that fails ends the frame short of its length, which the host refuses.
    async fn write_response<L: Link>(
        &mut self,
        link: &mut L,
        first: &Crossing,
    ) -> Result<(), HostGone> {
        link.write_all(&(first.total as u32).to_le_bytes()).await?;
        link.write_all(&self.resp[..first.part]).await?;
        let mut sent = first.part;
        while sent < first.total {
            let next = gateway::response_part(sent, first.total, &mut self.resp);
            if next.status != SG_OK || next.part == 0 {
                return Ok(());
            }
            link.write_all(&self.resp[..next.part]).await?;
            sent += next.part;
        }
        Ok(())
    }
}
