use std::borrow::Cow;

use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine as _,
};

const STANDARD_FLEXIBLE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(false),
);

pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    // Ordinary padded/unpadded input is borrowed. Only URL-safe or spaced
    // input needs a normalization buffer in addition to the decoded output.
    let bytes = input.as_bytes();
    let normalized: Cow<'_, [u8]> = if bytes
        .iter()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'-' | b'_'))
    {
        Cow::Owned(
            bytes
                .iter()
                .filter_map(|&byte| match byte {
                    b'-' => Some(b'+'),
                    b'_' => Some(b'/'),
                    byte if byte.is_ascii_whitespace() => None,
                    byte => Some(byte),
                })
                .collect(),
        )
    } else {
        Cow::Borrowed(bytes)
    };
    if let Some(byte) = normalized
        .iter()
        .find(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(format!("invalid base64 byte {byte}"));
    }
    if let Some(start) = normalized.iter().position(|byte| *byte == b'=') {
        let padding = &normalized[start..];
        if !normalized.len().is_multiple_of(4)
            || !(1..=2).contains(&padding.len())
            || padding.iter().any(|byte| *byte != b'=')
        {
            return Err("invalid base64 padding".into());
        }
    }
    STANDARD_FLEXIBLE
        .decode(normalized.as_ref())
        .map_err(|error| format!("invalid base64: {error}"))
}

pub(crate) fn encode_base64(input: &[u8]) -> String {
    STANDARD_FLEXIBLE.encode(input)
}
