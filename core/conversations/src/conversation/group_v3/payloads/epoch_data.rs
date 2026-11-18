use prost::Message;

use crate::ChatError;
use crate::conversation::mls_utils::EpochFingerprint;

const MAX_EPOCH_HISTORY: usize = 3;

#[derive(Debug, Clone, PartialEq)]
pub struct EpochData {
    epoch_num: u64,
    /// Newest first: `history[i]` is the fingerprint from `i` epochs back.
    history: Vec<EpochFingerprint>,
}

impl EpochData {
    /// The history of a member that enters the group at `epoch_num`, in the state `fingerprint`
    /// names.
    pub fn starting_at(epoch_num: u64, fingerprint: EpochFingerprint) -> Self {
        Self {
            epoch_num,
            history: vec![fingerprint],
        }
    }

    pub fn advance_to(&mut self, epoch: u64, fingerprint: EpochFingerprint) {
        self.epoch_num = epoch;
        self.history.insert(0, fingerprint);
        self.history.truncate(MAX_EPOCH_HISTORY);
    }

    /// Each epoch the history covers, newest first, with its fingerprint.
    pub fn epochs(&self) -> impl Iterator<Item = (u64, &EpochFingerprint)> {
        self.history
            .iter()
            .enumerate()
            .filter_map(|(back, fingerprint)| {
                Some((self.epoch_num.checked_sub(back as u64)?, fingerprint))
            })
    }

    #[cfg(test)]
    pub fn from_history(epoch_num: u64, history: Vec<EpochFingerprint>) -> Self {
        Self { epoch_num, history }
    }
}

/// Wire form of [`EpochData`].
#[derive(Clone, PartialEq, Message)]
pub(super) struct EpochDataProto {
    #[prost(uint64, tag = "1")]
    epoch_num: u64,
    #[prost(bytes = "vec", repeated, tag = "2")]
    history: Vec<Vec<u8>>,
}

impl From<&EpochData> for EpochDataProto {
    fn from(data: &EpochData) -> Self {
        Self {
            epoch_num: data.epoch_num,
            history: data
                .history
                .iter()
                .map(|fingerprint| fingerprint.as_bytes().to_vec())
                .collect(),
        }
    }
}

/// Rejects a fingerprint of the wrong length.
impl TryFrom<EpochDataProto> for EpochData {
    type Error = ChatError;

    fn try_from(proto: EpochDataProto) -> Result<Self, Self::Error> {
        let history = proto
            .history
            .iter()
            .map(|bytes| EpochFingerprint::try_from(bytes.as_slice()))
            .collect::<Result<_, _>>()
            .map_err(|_| ChatError::BadParsing("epoch fingerprint"))?;
        Ok(Self {
            epoch_num: proto.epoch_num,
            history,
        })
    }
}
