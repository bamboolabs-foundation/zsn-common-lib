#[derive(core::clone::Clone, core::marker::Copy, core::fmt::Debug)]
#[derive(core::cmp::Eq, core::cmp::PartialEq, core::cmp::PartialOrd, core::cmp::Ord)]
#[derive(parity_scale_codec::Decode, parity_scale_codec::Encode)]
#[derive(thiserror_no_std::Error, serde::Deserialize, serde::Serialize)]
#[repr(i32)]
pub enum Error {
    #[error("Entropy length is either 16, 20, 24, 28, or 32")]
    InvalidEntropyLength,
    #[error("Password too long, maximum password length is 512")]
    PasswordTooLong,
    #[error("Invalid mnemonic words")]
    InvalidMnemonicWords,
    #[error("Mnemonic words count is either 12, 15, 18, 21, 24")]
    InvalidMnemonicWordsCount,
    #[error("Invalid hex character")]
    InvalidHexCharacter,
    #[error("Invalid byte length")]
    InvalidByteLength,
    #[error("Invalid public key bytes")]
    InvalidPublicKeyBytes,
    #[error("Invalid Ss58 string")]
    InvalidSs58String,
    #[error("Invalid signature length")]
    InvalidSignatureLength,
    #[error("Invalid signature format")]
    InvalidSignatureFormat,
    #[error("Signing is denied")]
    NotOwned,
    #[error("Sender key should be owned during sending")]
    SenderKeyIsNotOwnedOnSending,
    #[error("Sender key should not be owned during receiving")]
    SenderKeyIsOwnedOnReceiving,
    #[error("Receiver key should not be owned during sending")]
    ReceiverKeyIsOwnedOnSending,
    #[error("Receiver key should be owned during receiving")]
    ReceiverKeyIsNotOwnedOnReceiving,
    #[error("EdwardsPoint cannot be decompressed")]
    EdwardsPointDecompressionFailure,
}
