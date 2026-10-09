use blake2::{Blake2b, Digest};

/// Track hash sizes in use across the crate.
pub mod hash_size {
    use blake2::digest::{
        consts::{U4, U6, U8, U32, U64},
        generic_array::ArrayLength,
        typenum::{IsLessOrEqual, NonZero},
    };

    pub trait HashLen
    where
        <Self::Size as IsLessOrEqual<U64>>::Output: NonZero,
    {
        type Size: ArrayLength<u8> + IsLessOrEqual<U64>;
    }

    /// This macro generates HashLen for the given typenum::length
    macro_rules! hash_sizes {
        ($($(#[$attr:meta])* $name:ident => $size:ty),* $(,)?) => {
            $(
                $(#[$attr])*
                pub struct $name;
                impl HashLen for $name { type Size = $size; }
            )*
        };
    }

    hash_sizes! {
        /// Conversation ID hash length
        ConvoId  => U6,
        /// Delivery Address length
        DeliveryAddr => U4,
        /// Causal history message ID hash length (256-bit, collision-resistant)
        MessageId => U32,
        /// Epoch state fingerprint length in a trace record
        EpochState => U8,
    }
}

/// This establishes an easy to use wrapper for hashes in this crate.
/// The output is formatted string of hex characters
pub fn blake2b_hex<LEN: hash_size::HashLen>(components: &[impl AsRef<[u8]>]) -> String {
    //A
    let mut hash = Blake2b::<LEN::Size>::new();

    for c in components {
        hash.update(c);
    }

    let output = hash.finalize();
    hex::encode(output)
}

/// Shorten byte slices for testing and logging
#[allow(unused)]
pub fn hex_trunc(data: &[u8]) -> String {
    if data.len() <= 8 {
        hex::encode(data)
    } else {
        format!(
            "{}..{}",
            hex::encode(&data[..4]),
            hex::encode(&data[data.len() - 4..])
        )
    }
}

pub fn trunc(data: &str) -> String {
    if data.chars().count() <= 8 {
        return data.to_string();
    }
    let head: String = data.chars().take(4).collect();
    let tail: String = data
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{head}..{tail}")
}
