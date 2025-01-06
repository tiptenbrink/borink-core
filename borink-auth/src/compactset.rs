use std::sync::{atomic::{self, AtomicU64}, Arc, OnceLock};

struct AtomicU64BitSet(AtomicU64);

pub trait CompactSet {
    fn exists(&self, num: u64) -> bool;
}

impl AtomicU64BitSet {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    fn exists(&self, n: u64) -> bool {
        if n >= 64 {
            panic!("Value must be less than 64!")
        }
        // 0 <= n < 64, so below does not overflow
        let one_at_bit_index = 1u64 << n;
        // shifting a 1 by n means we have a 64 bit number with a 1 at the nth position (0-indexed)
        let old_value = self.0.fetch_or(one_at_bit_index, atomic::Ordering::Relaxed);
        // now we OR with the existing value, which means we have a 1 at the nth position in our atom

        (old_value & one_at_bit_index) > 0
        // one_at_bit_index is 0 except at the nth position (0-indexed) and using AND will only return
        // a non-zero value if the nth position in old_value is 1
    }
}

pub trait AtomicBitSet {
    fn new() -> Self;

    fn max_n(&self) -> u64;

    fn create_up_to(&self, n: u64);

    fn exists(&self, n: u64) -> bool;

    fn reset(&self);
}

const SMALL_SIZE: usize = 32;

/// Occupies roughly 256 bytes for 2048 values
pub struct AtomicSmallBitSet {
    atoms: [AtomicU64BitSet; SMALL_SIZE],
}

// Initially only 16 bytes, but once the initial 64 values are exhausted the initial allocation take nearly 500 additional bytes
struct AtomicDynamicBitSet {
    initial: AtomicU64BitSet,
    max: u64,
    further: OnceLock<Arc<boxcar::Vec<AtomicU64BitSet>>>,
}

fn further_indexes(n: u64) -> (usize, u64) {
    let n_further = n - 64;
    let atom_index = (n_further as usize) / 64;
    let index_in_bucket = n_further - (atom_index * 64) as u64;

    (atom_index, index_in_bucket)
}

impl AtomicBitSet for AtomicDynamicBitSet {
    fn new() -> Self {
        Self {
            initial: AtomicU64BitSet::new(),
            // We have space  64 * (2^64 - 31 [the max length of the boxcar Vec]) + 64, which is more than u64::MAX
            max: u64::MAX,
            further: OnceLock::new(),
        }
    }

    fn create_up_to(&self, n: u64) {
        if n < 64 {
            return;
        }

        let further = self.further.get_or_init(|| Arc::new(boxcar::Vec::new()));

        let (atom_index, _) = further_indexes(n);

        while further.get(atom_index).is_none() {
            further.push(AtomicU64BitSet::new());
        }
    }

    /// Panics if exists is called for a number for which the bucket does not yet exist. Ensure `create_up_to` has been called for n before.
    fn exists(&self, n: u64) -> bool {
        if n < 64 {
            return self.initial.exists(n);
        }

        let further = self.further.get().unwrap();

        let (atom_index, index_in_bucket) = further_indexes(n);

        let bucket = further.get(atom_index).unwrap();

        bucket.exists(index_in_bucket)
    }

    fn max_n(&self) -> u64 {
        self.max
    }
    
    fn reset(&self) {
        self.initial.reset();
        if let Some(further) = self.further.get() {
            for (_, atom) in further.iter() {
                atom.reset();
            }
        }
    }
}

impl AtomicBitSet for AtomicSmallBitSet {
    fn new() -> Self {
        Self {
            atoms: [const { AtomicU64BitSet::new() }; SMALL_SIZE],
        }
    }

    fn max_n(&self) -> u64 {
        ((SMALL_SIZE as u64) * 64) - 1
    }

    fn create_up_to(&self, n: u64) {
        if n > self.max_n() {
            panic!("Cannot create for value greater than max!")
        }
    }

    fn exists(&self, n: u64) -> bool {
        if n > self.max_n() {
            panic!("Cannot check existence for greater than max!")
        }

        let atom_index = n / 64;
        let index_in_atom = n - (atom_index * 64);

        let atom = &self.atoms[index_in_atom as usize];

        atom.exists(index_in_atom)
    }
    
    fn reset(&self) {
        for a in &self.atoms {
            a.reset();
        }
    }
}

impl AtomicBitSet for AtomicU64BitSet {
    fn new() -> Self {
        Self::new()
    }

    fn max_n(&self) -> u64 {
        63
    }

    fn create_up_to(&self, n: u64) {
        if n > self.max_n() {
            panic!("Cannot create for value greater than max!")
        }
    }

    fn exists(&self, n: u64) -> bool {
        self.exists(n)
    }
    
    fn reset(&self) {
        self.0.store(0, atomic::Ordering::Relaxed);
    }
}

impl<T: AtomicBitSet> CompactSet for T {
    fn exists(&self, num: u64) -> bool {
        self.create_up_to(num);

        self.exists(num)
    }
}