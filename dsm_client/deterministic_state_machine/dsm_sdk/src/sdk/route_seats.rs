// SPDX-License-Identifier: MIT OR Apache-2.0

//! The storage interface route chains need (storage spec §9, §14).
//!
//! A writer puts a value at a cell's seats in route order, leader first, and
//! carries the chain built so far to each later seat. A verifier reads every
//! seat's entries with their arrival records, each seat's committed state as
//! a mirror holds it, and each seat's own mirror of the leader, then asks
//! Core to evaluate the chain (`dsm::route_chain`).
//!
//! Everything here is I/O against the members of the committed set, addressed
//! by the member ids the set commits. Nothing here evaluates a chain, counts
//! links, or decides a winner: that is Core's, over the evidence these calls
//! return.

use dsm::route_chain::CommittedAt;
use dsm::storage_cell::ArrivalRecord;

/// The five seats of a cell's route, as a writer and a verifier reach them.
pub trait RouteSeats: Send + Sync {
    /// Put the exact bytes of a `RouteEntry` at `seat`'s cell. `Ok` carries
    /// the arrival record the seat issued for those bytes, checked to name
    /// that seat and that cell; `Err` means the seat did not answer with one.
    fn put_entry(
        &self,
        seat: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
        entry: &[u8],
    ) -> impl core::future::Future<Output = Result<ArrivalRecord, String>> + Send;

    /// Everything `seat` holds at the cell, in arrival order, each value with
    /// its arrival record. `None` when the seat could not answer; an empty
    /// list is an answer.
    fn read_seat(
        &self,
        seat: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
    ) -> impl core::future::Future<Output = Option<Vec<(Vec<u8>, ArrivalRecord)>>> + Send;

    /// `seat`'s committed state for the cell: its latest ByteCommit as held
    /// by a mirror at another member, and `seat`'s proof against that root.
    /// `None` when no ByteCommit covering the cell has closed or none could be
    /// obtained.
    fn committed(
        &self,
        seat: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
    ) -> impl core::future::Future<Output = Option<CommittedAt>> + Send;

    /// `seat`'s own mirror of `leader`'s ByteCommits, with the leader's proof
    /// against the mirrored root: the coverage a later link at `seat` needs
    /// (§9, route chains, rule 4). `None` when `seat` holds no mirrored
    /// ByteCommit of the leader that covers the cell.
    fn leader_seen(
        &self,
        seat: &[u8],
        leader: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
    ) -> impl core::future::Future<Output = Option<CommittedAt>> + Send;
}
