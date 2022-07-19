//! Implements BinaryFuse8 filters.

use crate::{bfuse_contains_impl, bfuse_from_impl, Filter};
use alloc::{boxed::Box, vec::Vec};
use bytes::Bytes;
use core::convert::TryFrom;

#[cfg(feature = "serde")]
use bytes::{Buf, BufMut};
#[cfg(feature = "serde")]
use core::mem;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A `BinaryFuse8` filter is an Xor-like filter with 8-bit fingerprints arranged in a binary-partitioned [fuse graph].
/// `BinaryFuse8`s are similar to [`Fuse8`]s, but their construction is faster, uses less
/// memory, and is more likely to succeed.
///
/// A `BinaryFuse8` filter uses ≈9 bits per entry of the set is it constructed from, and has a false
/// positive rate of ≈2^-8 (<0.4%). As with other probabilistic filters, a higher number of entries decreases
/// the bits per entry but increases the false positive rate.
///
/// A `BinaryFuse8` is constructed from a set of 64-bit unsigned integers and is immutable.
/// Construction may fail, but usually only if there are duplicate keys.
///
/// ```
/// # extern crate alloc;
/// use xorf::{Filter, BinaryFuse8};
/// use core::convert::TryFrom;
/// # use alloc::vec::Vec;
/// # use rand::Rng;
///
/// # let mut rng = rand::thread_rng();
/// const SAMPLE_SIZE: usize = 1_000_000;
/// let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
/// let filter = BinaryFuse8::try_from(&keys).unwrap();
///
/// // no false negatives
/// for key in keys {
///     assert!(filter.contains(&key));
/// }
///
/// // bits per entry
/// let bpe = (filter.len() as f64) * 8.0 / (SAMPLE_SIZE as f64);
/// assert!(bpe < 9.1, "Bits per entry is {}", bpe);
///
/// // false positive rate
/// let false_positives: usize = (0..SAMPLE_SIZE)
///     .map(|_| rng.gen())
///     .filter(|n| filter.contains(n))
///     .count();
/// let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
/// assert!(fp_rate < 0.4, "False positive rate is {}", fp_rate);
/// ```
///
/// Serializing and deserializing `BinaryFuse8` filters can be enabled with the [`serde`] feature.
///
/// [fuse graph]: https://arxiv.org/abs/1907.04749
/// [`Fuse8`]: crate::Fuse8
/// [`serde`]: http://serde.rs
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct BinaryFuse8 {
    seed: u64,
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
    /// The fingerprints for the filter
    pub fingerprints: Bytes,
}

#[cfg(feature = "serde")]
impl BinaryFuse8 {
    const MIN_SERDE_SIZE: usize = mem::size_of::<u64>() + mem::size_of::<u32>() * 3;

    /// Serializes the `BinaryFuse8` to bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::MIN_SERDE_SIZE + self.fingerprints.len());
        buf.put_u64_le(self.seed);
        buf.put_u32_le(self.segment_length);
        buf.put_u32_le(self.segment_length_mask);
        buf.put_u32_le(self.segment_count_length);
        buf.extend_from_slice(self.fingerprints.chunk());
        buf
    }

    /// Deserializes a `BinaryFuse8` from `&[u8]`.
    pub fn try_from_slice(mut data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::MIN_SERDE_SIZE {
            return Err("data too short");
        }
        let seed = data.get_u64_le();
        let segment_length = data.get_u32_le();
        let segment_length_mask = data.get_u32_le();
        let segment_count_length = data.get_u32_le();
        let fingerprints = Bytes::from(data.to_vec());
        Ok(Self {
            seed,
            segment_length,
            segment_length_mask,
            segment_count_length,
            fingerprints,
        })
    }

    /// Deserializes a `BinaryFuse8` from `Bytes` which can avoid allocating and coping the
    /// fingerprints.
    pub fn try_from_bytes(data: &Bytes) -> Result<Self, &'static str> {
        if data.len() < Self::MIN_SERDE_SIZE {
            return Err("data too short");
        }
        let mut data = data.clone();
        let seed = data.get_u64_le();
        let segment_length = data.get_u32_le();
        let segment_length_mask = data.get_u32_le();
        let segment_count_length = data.get_u32_le();
        let fingerprints = data;
        Ok(Self {
            seed,
            segment_length,
            segment_length_mask,
            segment_count_length,
            fingerprints,
        })
    }
}

impl Filter<u64> for BinaryFuse8 {
    /// Returns `true` if the filter contains the specified key.
    /// Has a false positive rate of <0.4%.
    /// Has no false negatives.
    fn contains(&self, key: &u64) -> bool {
        bfuse_contains_impl!(*key, self, fingerprint u8)
    }

    fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

impl TryFrom<&[u64]> for BinaryFuse8 {
    type Error = &'static str;

    fn try_from(keys: &[u64]) -> Result<Self, Self::Error> {
        bfuse_from_impl!(keys fingerprint u8, max iter 1_000)
    }
}

impl TryFrom<&Vec<u64>> for BinaryFuse8 {
    type Error = &'static str;

    fn try_from(v: &Vec<u64>) -> Result<Self, Self::Error> {
        Self::try_from(v.as_slice())
    }
}

impl TryFrom<Vec<u64>> for BinaryFuse8 {
    type Error = &'static str;

    fn try_from(v: Vec<u64>) -> Result<Self, Self::Error> {
        Self::try_from(v.as_slice())
    }
}

#[cfg(test)]
mod test {
    use crate::{BinaryFuse8, Filter};
    use core::convert::TryFrom;

    use alloc::vec::Vec;
    use rand::Rng;

    #[test]
    fn test_initialization() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse8::try_from(&keys).unwrap();

        for key in keys {
            assert!(filter.contains(&key));
        }
    }

    #[test]
    fn test_bits_per_entry() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse8::try_from(&keys).unwrap();
        let bpe = (filter.len() as f64) * 8.0 / (SAMPLE_SIZE as f64);

        assert!(bpe < 9.1, "Bits per entry is {}", bpe);
    }

    #[test]
    fn test_false_positives() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse8::try_from(&keys).unwrap();

        let false_positives: usize = (0..SAMPLE_SIZE)
            .map(|_| rng.gen())
            .filter(|n| filter.contains(n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
        assert!(fp_rate < 0.4, "False positive rate is {}", fp_rate);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(
        expected = "Binary Fuse filters must be constructed from a collection containing all distinct keys."
    )]
    fn test_debug_assert_duplicates() {
        let _ = BinaryFuse8::try_from(vec![1, 2, 1]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_custom_serde() {
        const SAMPLE_SIZE: usize = 1_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse8::try_from(&keys).unwrap();
        let encoded = filter.to_vec();
        let decoded = BinaryFuse8::try_from_slice(&encoded).unwrap();
        assert_eq!(decoded.seed, filter.seed);
        assert_eq!(decoded.segment_length, filter.segment_length);
        assert_eq!(decoded.segment_length_mask, filter.segment_length_mask);
        assert_eq!(decoded.segment_count_length, filter.segment_count_length);
        assert_eq!(decoded.fingerprints, filter.fingerprints);

        let decoded = BinaryFuse8::try_from_bytes(&encoded.into()).unwrap();
        assert_eq!(decoded.seed, filter.seed);
        assert_eq!(decoded.segment_length, filter.segment_length);
        assert_eq!(decoded.segment_length_mask, filter.segment_length_mask);
        assert_eq!(decoded.segment_count_length, filter.segment_count_length);
        assert_eq!(decoded.fingerprints, filter.fingerprints);
    }

    #[test]
    fn test_build_failure_with_subtraction_overflow() {
        let key = rand::random();
        let filter = BinaryFuse8::try_from(vec![key]).unwrap();
        assert!(filter.contains(&key));
    }
}
