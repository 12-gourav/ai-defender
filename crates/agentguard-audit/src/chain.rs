//! Hash-chained records.
//!
//! `hash = SHA-256(prev_hash || canonical_json(event))`. The first record's `prev_hash` is all
//! zeros. The chain detects edits, deletions and reordering of stored records by anyone who
//! does not also recompute every subsequent hash; it is a tamper-evidence measure for review,
//! not a protection against a host user who controls the file.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuditError;
use crate::event::AuditEvent;

/// 32-byte digest serialised as lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32(pub [u8; 32]);

impl Digest32 {
    /// The genesis predecessor.
    pub const ZERO: Digest32 = Digest32([0u8; 32]);
}

impl Serialize for Digest32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&text, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(Digest32(bytes))
    }
}

/// An event plus its position in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainedRecord {
    /// 0-based sequence number.
    pub seq: u64,
    /// Hash of the previous record (zero for the first).
    pub prev_hash: Digest32,
    /// Hash of this record.
    pub hash: Digest32,
    /// The event.
    pub event: AuditEvent,
}

/// Compute the hash for `event` following `prev`.
pub fn compute_hash(prev: &Digest32, event: &AuditEvent) -> Result<Digest32, AuditError> {
    let body = serde_json::to_vec(event).map_err(AuditError::Serialise)?;
    let mut hasher = Sha256::new();
    hasher.update(prev.0);
    hasher.update(&body);
    Ok(Digest32(hasher.finalize().into()))
}

/// Build the next record in a chain.
pub fn append(
    prev: Option<&ChainedRecord>,
    event: AuditEvent,
) -> Result<ChainedRecord, AuditError> {
    let (seq, prev_hash) = match prev {
        Some(p) => (p.seq + 1, p.hash),
        None => (0, Digest32::ZERO),
    };
    let hash = compute_hash(&prev_hash, &event)?;
    Ok(ChainedRecord {
        seq,
        prev_hash,
        hash,
        event,
    })
}

/// Verify a sequence of records. Returns the index of the first bad record on failure.
pub fn verify(records: &[ChainedRecord]) -> Result<(), AuditError> {
    let mut expected_prev = Digest32::ZERO;
    for (index, record) in records.iter().enumerate() {
        let seq_ok = record.seq == index as u64;
        let prev_ok = record.prev_hash == expected_prev;
        let hash_ok = compute_hash(&record.prev_hash, &record.event)? == record.hash;
        if !(seq_ok && prev_ok && hash_ok) {
            return Err(AuditError::ChainBroken { index });
        }
        expected_prev = record.hash;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AuditEventKind;

    fn chain(n: usize) -> Vec<ChainedRecord> {
        let mut out: Vec<ChainedRecord> = Vec::new();
        for i in 0..n {
            let e = AuditEvent::new(AuditEventKind::HostCheck, &format!("r{i}"), "ok");
            let rec = append(out.last(), e).unwrap();
            out.push(rec);
        }
        out
    }

    #[test]
    fn valid_chain_verifies() {
        assert!(verify(&chain(5)).is_ok());
        assert!(verify(&[]).is_ok());
    }

    #[test]
    fn edit_delete_reorder_detected() {
        let mut edited = chain(4);
        edited[2].event.reason = agentguard_core::BoundedText::lossy("changed");
        assert!(matches!(
            verify(&edited),
            Err(AuditError::ChainBroken { index: 2 })
        ));

        let mut deleted = chain(4);
        deleted.remove(1);
        assert!(matches!(
            verify(&deleted),
            Err(AuditError::ChainBroken { index: 1 })
        ));

        let mut reordered = chain(4);
        reordered.swap(1, 2);
        assert!(matches!(
            verify(&reordered),
            Err(AuditError::ChainBroken { index: 1 })
        ));
    }

    #[test]
    fn digest_serde_round_trip() {
        let rec = chain(1).remove(0);
        let json = serde_json::to_string(&rec).unwrap();
        let back: ChainedRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
        assert!(json.contains(&"0".repeat(64)));
    }
}
