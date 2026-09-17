use openmls::{
    extensions::ExtensionType,
    prelude::{
        Capabilities,
        tls_codec::{Deserialize, Error as TlsError, Serialize, Size, VLByteSlice, VLBytes},
    },
};
use std::io::{Read, Write};

use crate::types::ConvoMetadata;

/// MLS extension type carrying our [`ConvoMetadata`]. In the private-use
/// range (0xF000–0xFFFF) reserved by RFC 9420 for non-registered extensions.
pub const GROUP_METADATA_EXTENSION_TYPE: u16 = 0xFF01;

pub fn capabilities_with_group_metadata() -> Capabilities {
    Capabilities::new(
        None, // default protocol versions
        None, // default ciphersuites
        Some(&[ExtensionType::Unknown(GROUP_METADATA_EXTENSION_TYPE)]),
        None, // default proposal types
        None, // default credential types
    )
}

/// Wire-format version of [`ConvoMetaInfo`], encoded as a `u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum ConvoMetaInfoVersion {
    V1 = 1,
}

impl TryFrom<u16> for ConvoMetaInfoVersion {
    type Error = TlsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            other => Err(TlsError::DecodingError(format!(
                "unknown ConvoMetaInfo version {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConvoMetaInfo {
    version: ConvoMetaInfoVersion,
    name: String,
    desc: String,
}

impl ConvoMetaInfo {
    pub fn new(name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            version: ConvoMetaInfoVersion::V1,
            name: name.into(),
            desc: desc.into(),
        }
    }

    pub fn to_extension_bytes(&self) -> Vec<u8> {
        // TLS presentation-language encoding — matches the MLS stack's wire
        // format. Writing to a Vec is infallible; the only error path is a
        // field exceeding tls_codec's ~1 GiB length cap, unreachable here.
        self.tls_serialize_detached()
            .expect("ConvoMetaInfo serialization to Vec is infallible")
    }

    pub fn from_extension_bytes(bytes: &[u8]) -> Result<Self, TlsError> {
        Self::tls_deserialize(&mut &bytes[..])
    }
}

// Each field is encoded as a variable-length opaque (`opaque <V>`); `Signer`
// and `String` aren't `tls_codec` types, so we encode/decode their UTF-8 bytes.
impl Size for ConvoMetaInfo {
    fn tls_serialized_len(&self) -> usize {
        (self.version as u16).tls_serialized_len()
            + VLByteSlice(self.name.as_bytes()).tls_serialized_len()
            + VLByteSlice(self.desc.as_bytes()).tls_serialized_len()
    }
}

impl Serialize for ConvoMetaInfo {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        let mut written = (self.version as u16).tls_serialize(writer)?;
        written += VLByteSlice(self.name.as_bytes()).tls_serialize(writer)?;
        written += VLByteSlice(self.desc.as_bytes()).tls_serialize(writer)?;
        Ok(written)
    }
}

impl Deserialize for ConvoMetaInfo {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, TlsError> {
        let version = ConvoMetaInfoVersion::try_from(u16::tls_deserialize(bytes)?)?;
        let name = vl_string(bytes)?;
        let desc = vl_string(bytes)?;
        Ok(Self {
            version,
            name,
            desc,
        })
    }
}

fn vl_string<R: Read>(bytes: &mut R) -> Result<String, TlsError> {
    let raw = VLBytes::tls_deserialize(bytes)?;
    String::from_utf8(raw.into())
        .map_err(|_| TlsError::DecodingError("invalid utf-8 in ConvoMetaInfo".into()))
}

impl From<ConvoMetaInfo> for ConvoMetadata {
    fn from(value: ConvoMetaInfo) -> Self {
        Self {
            name: value.name,
            desc: value.desc,
        }
    }
}
