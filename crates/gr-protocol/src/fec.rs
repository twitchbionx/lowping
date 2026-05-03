//! Reed-Solomon FEC over a sliding window of frames.
//!
//! Sender groups N data frames into a "block", computes K parity frames
//! using Reed-Solomon, and sends all N+K frames. Receiver can reconstruct
//! up to K lost frames per block from any N of the N+K received frames.
//!
//! Trade-offs:
//! - Higher K → higher loss tolerance, more bandwidth, more latency to recover
//! - Smaller N → faster recovery but more parity overhead per data frame
//! - Typical config: N=10, K=2 → 20% overhead, recovers 2/12 lost
//!
//! For loss-sensitive game traffic that tolerates only 50ms of latency, we
//! want small N (so we don't wait too long to fill a block before computing
//! parity). N=4-8 is a reasonable starting point.

use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FecError {
    #[error("invalid block configuration: data={data} parity={parity} (need data >= 1 and parity >= 1)")]
    InvalidConfig { data: usize, parity: usize },

    #[error("reed-solomon library error: {0}")]
    ReedSolomon(String),

    #[error("not enough shards to reconstruct: have {have}, need {need}")]
    InsufficientShards { have: usize, need: usize },

    #[error("inconsistent shard size: expected {expected}, got {got}")]
    InconsistentShardSize { expected: usize, got: usize },
}

pub type Result<T> = std::result::Result<T, FecError>;

/// Reed-Solomon encoder. Reusable across many blocks.
pub struct Encoder {
    rs: ReedSolomon,
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl Encoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0 || parity_shards == 0 {
            return Err(FecError::InvalidConfig {
                data: data_shards,
                parity: parity_shards,
            });
        }
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| FecError::ReedSolomon(e.to_string()))?;
        Ok(Self { rs, data_shards, parity_shards })
    }

    /// Compute parity shards. `data` must have exactly `data_shards` entries,
    /// all the same length. Output has `parity_shards` shards, same length each.
    pub fn encode(&self, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        if data.len() != self.data_shards {
            return Err(FecError::InvalidConfig {
                data: data.len(),
                parity: self.parity_shards,
            });
        }
        let shard_len = data[0].len();
        for (i, s) in data.iter().enumerate() {
            if s.len() != shard_len {
                return Err(FecError::InconsistentShardSize {
                    expected: shard_len,
                    got: s.len(),
                });
            }
            let _ = i;
        }
        // Build a single Vec<Vec<u8>> with both data and (initially empty) parity slots
        let mut shards: Vec<Vec<u8>> = data.to_vec();
        shards.extend((0..self.parity_shards).map(|_| vec![0u8; shard_len]));

        self.rs.encode(&mut shards)
            .map_err(|e| FecError::ReedSolomon(e.to_string()))?;
        Ok(shards.split_off(self.data_shards))
    }
}

/// Reed-Solomon decoder. Holds a partial set of shards and reconstructs once
/// enough are available.
pub struct Decoder {
    rs: ReedSolomon,
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl Decoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| FecError::ReedSolomon(e.to_string()))?;
        Ok(Self { rs, data_shards, parity_shards })
    }

    /// Try to reconstruct missing shards. `shards` is `data_shards + parity_shards`
    /// entries; missing entries are `None`. On success, all `None` slots in
    /// the data range (first `data_shards` entries) are filled.
    pub fn reconstruct_data(&self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        let total = self.data_shards + self.parity_shards;
        if shards.len() != total {
            return Err(FecError::InvalidConfig {
                data: shards.len(),
                parity: 0,
            });
        }
        let present = shards.iter().filter(|s| s.is_some()).count();
        if present < self.data_shards {
            return Err(FecError::InsufficientShards {
                have: present,
                need: self.data_shards,
            });
        }
        self.rs.reconstruct_data(shards)
            .map_err(|e| FecError::ReedSolomon(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode_with_no_loss_yields_original_data() {
        let enc = Encoder::new(4, 2).unwrap();
        let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8 + 1; 100]).collect();
        let parity = enc.encode(&data).unwrap();
        assert_eq!(parity.len(), 2);
        // No loss: data already complete; reconstruct should be a no-op
        let dec = Decoder::new(4, 2).unwrap();
        let mut shards: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        shards.extend(parity.into_iter().map(Some));
        dec.reconstruct_data(&mut shards).unwrap();
        for (i, s) in shards.iter().take(4).enumerate() {
            assert_eq!(s.as_ref().unwrap(), &vec![i as u8 + 1; 100]);
        }
    }

    #[test]
    fn recovers_one_lost_data_shard() {
        let enc = Encoder::new(4, 2).unwrap();
        let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8 + 10; 50]).collect();
        let parity = enc.encode(&data).unwrap();
        let dec = Decoder::new(4, 2).unwrap();

        // Lose data shard at index 1
        let mut shards: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        shards[1] = None;
        shards.extend(parity.into_iter().map(Some));

        dec.reconstruct_data(&mut shards).unwrap();
        assert_eq!(shards[1].as_ref().unwrap(), &vec![11u8; 50]);
    }

    #[test]
    fn recovers_two_lost_data_shards() {
        let enc = Encoder::new(4, 2).unwrap();
        let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8 * 7; 30]).collect();
        let parity = enc.encode(&data).unwrap();
        let dec = Decoder::new(4, 2).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        shards[0] = None;
        shards[3] = None;
        shards.extend(parity.into_iter().map(Some));

        dec.reconstruct_data(&mut shards).unwrap();
        assert_eq!(shards[0].as_ref().unwrap(), &vec![0u8; 30]);
        assert_eq!(shards[3].as_ref().unwrap(), &vec![21u8; 30]);
    }

    #[test]
    fn three_losses_with_only_two_parity_shards_fails() {
        let enc = Encoder::new(4, 2).unwrap();
        let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 20]).collect();
        let parity = enc.encode(&data).unwrap();
        let dec = Decoder::new(4, 2).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        shards[0] = None;
        shards[1] = None;
        shards[2] = None;
        shards.extend(parity.into_iter().map(Some));

        let err = dec.reconstruct_data(&mut shards).unwrap_err();
        assert!(matches!(err, FecError::InsufficientShards { .. }));
    }
}
