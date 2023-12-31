#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(all(feature = "opt-aarch64", feature = "opt-intel"))]
compile_error!("Feature \"opt-aarch64\" can't be combined with \"opt-intel\".");

#[cfg(all(feature = "opt-aarch64", feature = "wasm32"))]
compile_error!("Feature \"opt-aarch64\" can't be combined with \"wasm32\".");

#[cfg(all(feature = "opt-intel", feature = "wasm32"))]
compile_error!("Feature \"opt-intel\" can't be combined with \"wasm32\".");

pub mod errors;
pub mod mnemonic;

pub type Result<T> = core::result::Result<T, errors::Error>;
pub type PrivateKeyBytes = zeroize::Zeroizing<[u8; CryptographicIdentity::LEN_PRIVATE_KEY]>;
pub type PrivateKeyHex =
    zeroize::Zeroizing<arrayvec::ArrayString<{ CryptographicIdentity::LEN_PRIVATE_KEY * 2 }>>;
pub type PublicKeyBytes = [u8; CryptographicIdentity::LEN_PUBLIC_KEY];
pub type PublicKeyHex = arrayvec::ArrayString<{ CryptographicIdentity::LEN_PUBLIC_KEY * 2 }>;
pub type SharedKey = zeroize::Zeroizing<SharedKeyBytes>;
pub type SharedKeyBytes = [u8; CryptographicIdentity::LEN_SHARED_KEY];
pub type SignatureBytes = [u8; CryptographicIdentity::LEN_SIGNATURE];
pub type Ss58String = arrayvec::ArrayString<{ CryptographicIdentity::SS58_STRING_MAX_LENGTH }>;

use core::ops::{Deref, DerefMut};
use core::str::FromStr;
use digest::Digest;
use zeroize::Zeroize;

#[derive(core::clone::Clone)]
#[derive(zeroize::ZeroizeOnDrop)]
pub enum CryptographicIdentity {
    OwnedKey { keypair: ed25519_compact::KeyPair },
    OthersKey { public: ed25519_compact::PublicKey },
}

impl core::hash::Hash for CryptographicIdentity {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.get_verifier().hash(state);
    }
}

impl core::cmp::Eq for CryptographicIdentity {}

impl core::cmp::PartialEq for CryptographicIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.get_verifier().eq(other.get_verifier())
    }
}

impl core::cmp::PartialOrd for CryptographicIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::cmp::Ord for CryptographicIdentity {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.get_verifier().as_ref().cmp(other.get_verifier().as_ref())
    }
}

impl core::convert::From<ed25519_compact::PublicKey> for CryptographicIdentity {
    fn from(value: ed25519_compact::PublicKey) -> Self {
        Self::OthersKey {
            public: value,
        }
    }
}

impl core::convert::From<ed25519_compact::KeyPair> for CryptographicIdentity {
    fn from(value: ed25519_compact::KeyPair) -> Self {
        Self::OwnedKey {
            keypair: value,
        }
    }
}

impl core::convert::From<ed25519_compact::SecretKey> for CryptographicIdentity {
    fn from(value: ed25519_compact::SecretKey) -> Self {
        let pk = value.public_key();

        Self::OwnedKey {
            keypair: ed25519_compact::KeyPair {
                pk,
                sk: value,
            },
        }
    }
}

impl core::convert::From<crate::mnemonic::MnemonicPhrase> for CryptographicIdentity {
    fn from(value: crate::mnemonic::MnemonicPhrase) -> Self {
        let secret_seed = value.try_get_secret_seed("").expect("Should be infallible!");
        let secret_seed =
            ed25519_compact::Seed::from_slice(secret_seed.deref()).expect("Should be infallible!");
        let keypair = ed25519_compact::KeyPair::from_seed(secret_seed);
        secret_seed.wipe();

        Self::OwnedKey {
            keypair,
        }
    }
}

impl core::fmt::Debug for CryptographicIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.get_verifier().fmt(f)
    }
}

impl core::fmt::Display for CryptographicIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.get_ss58_identity())
    }
}

impl CryptographicIdentity {
    pub const LEN_PRIVATE_KEY: usize = 32;
    pub const LEN_PUBLIC_KEY: usize = 32;
    pub const LEN_SHARED_KEY: usize = 32;
    pub const LEN_SIGNATURE: usize = 64;
    pub const SS58_BYTES_LENGTH: usize = Self::LEN_PUBLIC_KEY + Self::SS58_BYTES_SUFFIX_PREFIX_LENGTH;
    pub const SS58_BYTES_PREFIX_LENGTH: usize = 2;
    pub const SS58_BYTES_SUFFIX_INDEX: usize = Self::SS58_BYTES_LENGTH - Self::SS58_BYTES_SUFFIX_LENGTH;
    pub const SS58_BYTES_SUFFIX_LENGTH: usize = 2;
    pub const SS58_BYTES_SUFFIX_PREFIX_LENGTH: usize =
        Self::SS58_BYTES_PREFIX_LENGTH + Self::SS58_BYTES_SUFFIX_LENGTH;
    pub const SS58_IDENTIFIER: &'static [u8; 7] = b"SS58PRE";
    pub const SS58_PREFIX: u16 = ss58_registry::Ss58AddressFormatRegistry::IdentitasAccount as u16;
    pub const SS58_STRING_LENGTH_RANGE: core::ops::RangeInclusive<usize> =
        Self::SS58_STRING_MIN_LENGTH..=Self::SS58_STRING_MAX_LENGTH;
    pub const SS58_STRING_MAX_LENGTH: usize = 50;
    pub const SS58_STRING_MIN_LENGTH: usize = Self::SS58_BYTES_SUFFIX_PREFIX_LENGTH;

    pub fn generate() -> Self {
        let mut random_bytes = zeroize::Zeroizing::new([0u8; Self::LEN_PRIVATE_KEY]);
        getrandom::getrandom(random_bytes.deref_mut()).expect("Catasthropic cryptography failure!");

        Self::try_from_private_bytes(random_bytes.deref()).expect("Should be infallible!")
    }

    pub fn try_from_phrase(phrase: &str, password: &str) -> crate::Result<Self> {
        let mnemonic_phrase = crate::mnemonic::MnemonicPhrase::try_from(phrase)?;

        Self::try_from_private_bytes(&mnemonic_phrase.try_get_secret_seed(password)?[..Self::LEN_PRIVATE_KEY])
    }

    pub fn try_from_public_bytes(source: &[u8]) -> crate::Result<Self> {
        let public = ed25519_compact::PublicKey::from_slice(source)
            .map_err(|_| crate::errors::Error::InvalidPublicKeyBytes)?;

        crate::Result::Ok(Self::OthersKey {
            public,
        })
    }

    pub fn try_from_public_hex(source: &str) -> crate::Result<Self> {
        let source = if source.starts_with("0x") {
            source.strip_prefix("0x").unwrap()
        } else {
            source
        };

        let mut public_bytes = [0u8; Self::LEN_PUBLIC_KEY];
        hex::decode_to_slice(source, &mut public_bytes)
            .map_err(|_| crate::errors::Error::InvalidHexCharacter)?;

        Self::try_from_public_bytes(&public_bytes)
    }

    pub fn try_from_ss58(source: &str) -> crate::Result<Self> {
        let char_count = source.len();

        if !Self::SS58_STRING_LENGTH_RANGE.contains(&char_count) {
            return crate::Result::Err(crate::errors::Error::InvalidSs58String);
        }

        let mut hasher = blake2::Blake2b512::new();
        hasher.update(Self::SS58_IDENTIFIER);
        let mut hash_buffer = [0u8; 64]; // 512-bit
        let mut decoded_buffer = [0u8; Self::SS58_BYTES_LENGTH];
        let decode_length = bs58::decode(source)
            .onto(&mut decoded_buffer)
            .map_err(|_| crate::errors::Error::InvalidSs58String)?;
        let mut public_key_bytes = [0u8; Self::LEN_PUBLIC_KEY];

        if (0..64).contains(&decoded_buffer[0]) {
            // sort ident decode

            if decode_length != 35 {
                return Err(crate::errors::Error::InvalidSs58String);
            }

            hasher.update(&decoded_buffer[..33]);
            hasher.finalize_into((&mut hash_buffer).into());

            if hash_buffer[..2] != decoded_buffer[33..35] {
                return Err(crate::errors::Error::InvalidSs58String);
            }

            public_key_bytes.copy_from_slice(&decoded_buffer[1..33]);
        } else {
            // long ident decode

            if decode_length != 36 {
                return Err(crate::errors::Error::InvalidSs58String);
            }

            hasher.update(&decoded_buffer[..34]);
            hasher.finalize_into((&mut hash_buffer).into());

            if hash_buffer[..2] != decoded_buffer[34..36] {
                return Err(crate::errors::Error::InvalidSs58String);
            }

            public_key_bytes.copy_from_slice(&decoded_buffer[2..34]);
        }

        Self::try_from_public_bytes(&public_key_bytes)
    }

    pub fn try_from_private_bytes(source: &[u8]) -> crate::Result<Self> {
        let secret_seed =
            ed25519_compact::Seed::from_slice(source).map_err(|_| crate::errors::Error::InvalidByteLength)?;
        let keypair = ed25519_compact::KeyPair::from_seed(secret_seed);
        secret_seed.wipe();

        crate::Result::Ok(Self::OwnedKey {
            keypair,
        })
    }

    pub fn try_from_private_hex(source: &str) -> crate::Result<Self> {
        let source = if source.starts_with("0x") {
            source.strip_prefix("0x").unwrap()
        } else {
            source
        };

        let mut private_bytes = zeroize::Zeroizing::new([0u8; Self::LEN_PUBLIC_KEY]);
        hex::decode_to_slice(source, private_bytes.deref_mut())
            .map_err(|_| crate::errors::Error::InvalidHexCharacter)?;

        Self::try_from_private_bytes(private_bytes.deref())
    }

    pub fn get_ss58(&self, prefix: u16) -> Ss58String {
        let verifier = self.get_verifier();
        let public_bytes = verifier.as_ref();
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(Self::SS58_IDENTIFIER);
        let mut hash_buffer = [0u8; 64]; // 512-bit
        let mut string_buffer = [0u8; { Self::SS58_BYTES_LENGTH * 2 }];
        let mut version_buffer = [0u8; Self::SS58_BYTES_LENGTH];
        let ident: u16 = prefix & 0b0011_1111_1111_1111; // 14-bit only
        let sort_ident = (0..64).contains(&ident);
        let string_length;

        if sort_ident {
            version_buffer[0] = ident as u8;
            version_buffer[1..33].copy_from_slice(public_bytes);
            hasher.update(&version_buffer[..33]);
            hasher.finalize_into((&mut hash_buffer).into());
            version_buffer[33..35].copy_from_slice(&hash_buffer[..2]);
            string_length = bs58::encode(&version_buffer[..35])
                .onto(string_buffer.as_mut())
                .unwrap();
        } else {
            let first = (((ident & 0b0000_0000_1111_1100) as u8) >> 2) | 0b01000000;
            let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
            version_buffer[0] = first | 0b01000000;
            version_buffer[1] = second;
            version_buffer[2..34].copy_from_slice(public_bytes);
            hasher.update(&version_buffer[..34]);
            hasher.finalize_into((&mut hash_buffer).into());
            version_buffer[34..36].copy_from_slice(&hash_buffer[..2]);
            string_length = bs58::encode(&version_buffer[..])
                .onto(string_buffer.as_mut())
                .unwrap();
        }

        let utf8_str = core::str::from_utf8(&string_buffer[..string_length]).expect("Should be infallible!");

        Ss58String::from_str(utf8_str).expect("Should be infallible!")
    }

    pub fn get_ss58_identity(&self) -> Ss58String {
        self.get_ss58(Self::SS58_PREFIX)
    }

    pub fn is_owned(&self) -> bool {
        matches!(self, Self::OwnedKey { .. })
    }

    pub fn try_sign(&self, message: &[u8]) -> crate::Result<SignatureBytes> {
        let signature = self.try_get_keypair()?.sk.sign(message, None);
        let mut signature_bytes = [0u8; Self::LEN_SIGNATURE];
        signature_bytes.copy_from_slice(signature.deref());

        crate::Result::Ok(signature_bytes)
    }

    pub fn try_sign_digest<D: digest::Digest<OutputSize = typenum::U64>>(
        &self,
        digest: D,
        context: Option<&[u8]>,
    ) -> crate::Result<SignatureBytes> {
        let mut seed = self.try_get_keypair()?.sk.seed();
        let sk_dalek = ed25519_dalek::SigningKey::from_bytes(seed.deref());
        let signature = sk_dalek
            .sign_prehashed(digest, context)
            .expect("Catasthropic cryptography failure!");
        seed.zeroize();

        crate::Result::Ok(signature.to_bytes())
    }

    pub fn try_get_streaming_signer(&self) -> crate::Result<StreamingSigner> {
        let sk = &self.try_get_keypair()?.sk;
        let mut noise = [0u8; ed25519_compact::Noise::BYTES];
        getrandom::getrandom(&mut noise).expect("Catasthropic cryptography failure!");
        let noise = ed25519_compact::Noise::new(noise);

        crate::Result::Ok(StreamingSigner {
            inner: sk.sign_incremental(noise),
        })
    }

    pub fn try_verify(&self, signature: &[u8], message: &[u8]) -> crate::Result<bool> {
        if signature.len() != Self::LEN_SIGNATURE {
            return crate::Result::Err(crate::errors::Error::InvalidSignatureLength);
        }

        let valid_signature = ed25519_compact::Signature::from_slice(signature)
            .map_err(|_| crate::errors::Error::InvalidSignatureFormat)?;

        crate::Result::Ok(self.get_verifier().verify(message, &valid_signature).is_ok())
    }

    pub fn try_verify_digest<D: digest::Digest<OutputSize = typenum::U64>>(
        &self,
        digest: D,
        signature: &[u8],
        context: Option<&[u8]>,
    ) -> crate::Result<bool> {
        if signature.len() != Self::LEN_SIGNATURE {
            return crate::Result::Err(crate::errors::Error::InvalidSignatureLength);
        }

        let valid_signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| crate::errors::Error::InvalidSignatureFormat)?;
        let pk_bytes = self.get_verifier().deref();
        let pk_dalek =
            ed25519_dalek::VerifyingKey::from_bytes(pk_bytes).expect("Catasthropic cryptography failure!");

        crate::Result::Ok(
            pk_dalek
                .verify_prehashed(digest, context, &valid_signature)
                .is_ok(),
        )
    }

    pub fn try_get_streaming_verifier(&self, signature: &[u8]) -> crate::Result<StreamingVerifier> {
        if signature.len() != Self::LEN_SIGNATURE {
            return crate::Result::Err(crate::errors::Error::InvalidSignatureLength);
        }

        let valid_signature = ed25519_compact::Signature::from_slice(signature)
            .map_err(|_| crate::errors::Error::InvalidSignatureFormat)?;
        let inner = self
            .get_verifier()
            .verify_incremental(&valid_signature)
            .expect("Should be infallible!");

        crate::Result::Ok(StreamingVerifier {
            inner,
        })
    }

    pub fn try_create_sending_key(
        &self,
        context: &str,
        receiver_identity: &Self,
    ) -> crate::Result<SharedKey> {
        if receiver_identity.is_owned() {
            return crate::Result::Err(crate::errors::Error::ReceiverKeyIsOwnedOnSending);
        }

        let sender_bytes = self.get_verifier().as_ref();
        let shared_compressed = Self::try_get_shared_compressed_edwards_y(
            self.try_get_keypair()?,
            receiver_identity.get_verifier(),
        )?;
        let mut master_key = zeroize::Zeroizing::new([0u8; 64]);
        master_key[..32].copy_from_slice(sender_bytes);
        master_key[32..].copy_from_slice(shared_compressed.as_bytes());

        Ok(zeroize::Zeroizing::new(blake3::derive_key(
            context,
            master_key.deref(),
        )))
    }

    pub fn try_create_receiving_key(
        &self,
        context: &str,
        sender_identity: &Self,
    ) -> crate::Result<SharedKey> {
        if sender_identity.is_owned() {
            return crate::Result::Err(crate::errors::Error::SenderKeyIsOwnedOnReceiving);
        }

        let sender_bytes = sender_identity.get_verifier().as_ref();
        let shared_compressed = Self::try_get_shared_compressed_edwards_y(
            self.try_get_keypair()?,
            sender_identity.get_verifier(),
        )?;
        let mut master_key = zeroize::Zeroizing::new([0u8; 64]);
        master_key[..32].copy_from_slice(sender_bytes);
        master_key[32..].copy_from_slice(shared_compressed.as_bytes());

        Ok(zeroize::Zeroizing::new(blake3::derive_key(
            context,
            master_key.deref(),
        )))
    }

    pub fn try_get_private_bytes(&self) -> crate::Result<&[u8]> {
        crate::Result::Ok(&self.try_get_keypair()?.sk[..Self::LEN_PRIVATE_KEY])
    }

    pub fn try_get_private_hex(&self) -> crate::Result<PrivateKeyHex> {
        let private_bytes = self.try_get_private_bytes()?;
        let mut string_buffer = zeroize::Zeroizing::new([0u8; Self::LEN_PRIVATE_KEY * 2]);
        hex::encode_to_slice(private_bytes, string_buffer.deref_mut()).expect("Should be infallible!");

        let private_hex = zeroize::Zeroizing::new(
            arrayvec::ArrayString::<{ CryptographicIdentity::LEN_PRIVATE_KEY * 2 }>::from_byte_string(
                string_buffer.deref(),
            )
            .expect("Should be infallible!"),
        );

        crate::Result::Ok(private_hex)
    }

    pub fn get_public_bytes(&self) -> &[u8] {
        self.get_verifier().deref()
    }

    pub fn get_public_hex(&self) -> PublicKeyHex {
        let public_bytes = self.get_public_bytes();
        let mut string_buffer = [0u8; Self::LEN_PUBLIC_KEY * 2];
        hex::encode_to_slice(public_bytes, &mut string_buffer).expect("Should be infallible!");

        PublicKeyHex::from_byte_string(&string_buffer).expect("Should be infallible!")
    }

    pub fn into_others(self) -> Self {
        Self::OthersKey {
            public: *self.get_verifier(),
        }
    }

    fn try_get_shared_compressed_edwards_y(
        keypair: &ed25519_compact::KeyPair,
        verifying_key: &ed25519_compact::PublicKey,
    ) -> crate::Result<zeroize::Zeroizing<curve25519_dalek::edwards::CompressedEdwardsY>> {
        let mut pk_bytes = [0u8; Self::LEN_PUBLIC_KEY];
        pk_bytes.copy_from_slice(verifying_key.as_ref());
        let pk_point = curve25519_dalek::edwards::CompressedEdwardsY(pk_bytes)
            .decompress()
            .ok_or(crate::errors::Error::EdwardsPointDecompressionFailure)?;
        let sk_hash: [u8; 64] = sha2::Sha512::default()
            .chain_update(&keypair.sk[..Self::LEN_PRIVATE_KEY])
            .finalize()
            .into();
        let mut sk_scalar_bytes = [0u8; 32];
        sk_scalar_bytes.copy_from_slice(&sk_hash[..32]);
        let sk_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(
            curve25519_dalek::scalar::clamp_integer(sk_scalar_bytes),
        );

        crate::Result::Ok(zeroize::Zeroizing::new((pk_point * sk_scalar).compress()))
    }

    fn try_get_keypair(&self) -> crate::Result<&ed25519_compact::KeyPair> {
        match self {
            Self::OthersKey {
                ..
            } => crate::Result::Err(crate::errors::Error::NotOwned),
            Self::OwnedKey {
                keypair,
            } => crate::Result::Ok(keypair),
        }
    }

    fn get_verifier(&self) -> &ed25519_compact::PublicKey {
        match self {
            Self::OthersKey {
                public,
            } => public,
            Self::OwnedKey {
                keypair,
            } => &keypair.pk,
        }
    }
}

pub struct StreamingSigner {
    inner: ed25519_compact::SigningState,
}

impl StreamingSigner {
    pub fn update(&mut self, message_chunk: &[u8]) {
        self.inner.absorb(message_chunk);
    }

    pub fn finalize(self) -> SignatureBytes {
        let signature = self.inner.sign();
        let mut signature_bytes = [0u8; CryptographicIdentity::LEN_SIGNATURE];
        signature_bytes.copy_from_slice(signature.deref());

        signature_bytes
    }
}

pub struct StreamingVerifier {
    inner: ed25519_compact::VerifyingState,
}

impl StreamingVerifier {
    pub fn update(&mut self, message_chunk: &[u8]) {
        self.inner.absorb(message_chunk);
    }

    pub fn finalize(self) -> bool {
        self.inner.verify().is_ok()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::mnemonic::MnemonicPhrase;
    use alloc::format;
    use alloc::string::ToString;
    use digest::Digest;
    use getrandom::getrandom;
    use sha2::Sha512;
    use sp_core::crypto::{AccountId32, Ss58Codec};
    use sp_core::ed25519::{Pair as Ed25519KeyPair, Signature};
    use sp_core::Pair;
    use ss58_registry::{Ss58AddressFormat, Ss58AddressFormatRegistry};
    use test_case::test_case;

    #[cfg(debug_assertions)]
    const TEST_REPETITIONS: usize = 32;
    #[cfg(not(debug_assertions))]
    const TEST_REPETITIONS: usize = 512;
    const ALICE_MINISECRET_HEX: &str = "0xabf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115";
    const ALICE_PUBLIC_HEX: &str = "0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee";
    const ALICE_PUBLIC_SS58: &str = "idXc9jR6fTzwS1Avubt5jGPYwjzhBDL7bWHFQCWhax1rskKfT";
    const SHARED_SECRET_CONTEXT: &str = "zsn 1.0";

    #[test]
    fn substrate_ss58_compatibilities() {
        let alice_identitas = CryptographicIdentity::try_from_private_hex(ALICE_MINISECRET_HEX).unwrap();
        let alice_identitas_public = CryptographicIdentity::try_from_public_hex(ALICE_PUBLIC_HEX).unwrap();
        let alice_identitas_from_ss58 = CryptographicIdentity::try_from_ss58(ALICE_PUBLIC_SS58).unwrap();
        let alice_substrate = Ed25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let alice_identitas_ss58 = alice_identitas.to_string();
        let alice_substrate_ss58 = AccountId32::from(alice_substrate.public())
            .to_ss58check_with_version(Ss58AddressFormat::custom(CryptographicIdentity::SS58_PREFIX));
        let alice_secret_hex = format!("0x{}", alice_identitas.try_get_private_hex().unwrap().deref());
        let alice_public_hex = format!("0x{}", alice_identitas.get_public_hex());

        assert_eq!(alice_identitas, alice_identitas_public);
        assert_eq!(alice_identitas, alice_identitas_from_ss58);
        assert_eq!(alice_identitas_ss58.as_str(), &alice_substrate_ss58);
        assert_eq!(alice_identitas_ss58.as_str(), ALICE_PUBLIC_SS58);
        assert_eq!(&alice_secret_hex, ALICE_MINISECRET_HEX);
        assert_eq!(&alice_public_hex, ALICE_PUBLIC_HEX);
    }

    #[test_case(24 ; "mnemonic-24")]
    #[test_case(21 ; "mnemonic-21")]
    #[test_case(18 ; "mnemonic-18")]
    #[test_case(15 ; "mnemonic-15")]
    #[test_case(12 ; "mnemonic-12")]
    fn substrate_signature_compatibilities(word_count: usize) {
        for _ in 0..TEST_REPETITIONS {
            let mut random_message = [0u8; 64 * 1024];
            getrandom(&mut random_message).unwrap();
            let random_mnemonic = MnemonicPhrase::try_generate_with_count(word_count).unwrap();
            let random_identity = CryptographicIdentity::try_from_phrase(&random_mnemonic, "").unwrap();
            let (substrate_keypair, _) = Ed25519KeyPair::from_phrase(&random_mnemonic, None).unwrap();
            let signature_identitas = random_identity.try_sign(&random_message).unwrap();
            let signature_substrate = substrate_keypair.sign(&random_message).0;
            let verification_identitas = random_identity
                .try_verify(&signature_substrate, &random_message)
                .unwrap();
            let verification_substrate = Ed25519KeyPair::verify(
                &Signature::from_raw(signature_identitas),
                random_message,
                &substrate_keypair.public(),
            );
            let ss58_identitas = random_identity.to_string();
            let ss58_substrate = AccountId32::from(substrate_keypair.public())
                .to_ss58check_with_version(Ss58AddressFormat::custom(CryptographicIdentity::SS58_PREFIX));
            let ss58_goro = random_identity.get_ss58(Ss58AddressFormatRegistry::GoroAccount as u16);
            let ss58_substrate_goro = AccountId32::from(substrate_keypair.public())
                .to_ss58check_with_version(Ss58AddressFormatRegistry::GoroAccount.into());

            assert!(verification_identitas);
            assert!(verification_substrate);
            assert_eq!(ss58_identitas, ss58_substrate);
            assert_eq!(ss58_goro.as_str(), &ss58_substrate_goro);
        }
    }

    #[test]
    fn shared_secret_is_valid_for_both_end() {
        for _ in 0..TEST_REPETITIONS {
            let random_sender_owned = CryptographicIdentity::generate();
            let random_sender_others = random_sender_owned.clone().into_others();

            assert_eq!(random_sender_owned, random_sender_others);

            let random_receiver_owned = CryptographicIdentity::generate();
            let random_receiver_others = random_receiver_owned.clone().into_others();

            assert_eq!(random_receiver_owned, random_receiver_others);

            let sending_key = random_sender_owned
                .try_create_sending_key(SHARED_SECRET_CONTEXT, &random_receiver_others)
                .unwrap();
            let receiving_key = random_receiver_owned
                .try_create_receiving_key(SHARED_SECRET_CONTEXT, &random_sender_others)
                .unwrap();

            assert_eq!(sending_key.deref(), receiving_key.deref());
        }
    }

    #[test_case(24 ; "mnemonic-24")]
    #[test_case(21 ; "mnemonic-21")]
    #[test_case(18 ; "mnemonic-18")]
    #[test_case(15 ; "mnemonic-15")]
    #[test_case(12 ; "mnemonic-12")]
    fn streaming_signature_is_substrate_compatible(word_count: usize) {
        for _ in 0..TEST_REPETITIONS {
            let mut big_random_message = [0u8; 512 * 1024];
            getrandom(&mut big_random_message).unwrap();
            let random_mnemonic = MnemonicPhrase::try_generate_with_count(word_count).unwrap();
            let random_identity = CryptographicIdentity::try_from_phrase(&random_mnemonic, "").unwrap();
            let (substrate_keypair, _) = Ed25519KeyPair::from_phrase(&random_mnemonic, None).unwrap();
            let mut streaming_signer = random_identity.try_get_streaming_signer().unwrap();

            for chunk in big_random_message.chunks_exact(128) {
                streaming_signer.update(chunk);
            }

            let signature_identitas = streaming_signer.finalize();
            let signature_substrate = substrate_keypair.sign(&big_random_message).0;
            let mut streaming_verifier = random_identity
                .try_get_streaming_verifier(&signature_substrate)
                .unwrap();

            for chunk in big_random_message.chunks_exact(128) {
                streaming_verifier.update(chunk);
            }

            let verification_identitas = streaming_verifier.finalize();
            let verification_substrate = Ed25519KeyPair::verify(
                &Signature::from_raw(signature_identitas),
                big_random_message,
                &substrate_keypair.public(),
            );

            assert!(verification_identitas);
            assert!(verification_substrate);
        }
    }

    #[test_case(24 ; "mnemonic-24")]
    #[test_case(21 ; "mnemonic-21")]
    #[test_case(18 ; "mnemonic-18")]
    #[test_case(15 ; "mnemonic-15")]
    #[test_case(12 ; "mnemonic-12")]
    fn digest_signature_is_verifiable(word_count: usize) {
        for _ in 0..TEST_REPETITIONS {
            let mut random_message = [0u8; 1024];
            getrandom(&mut random_message).unwrap();
            let random_mnemonic = MnemonicPhrase::try_generate_with_count(word_count).unwrap();
            let random_identity_owned = CryptographicIdentity::try_from_phrase(&random_mnemonic, "").unwrap();
            let random_identity_others = random_identity_owned.clone().into_others();
            let mut digest = Sha512::new();
            digest.update(random_message);
            let signature = random_identity_owned
                .try_sign_digest(digest, Some(b"ZSN Context"))
                .unwrap();
            let mut digest = Sha512::new();
            digest.update(random_message);
            let verification_result = random_identity_others
                .try_verify_digest(digest, &signature, Some(b"ZSN Context"))
                .unwrap();

            assert!(verification_result);
        }
    }
}
