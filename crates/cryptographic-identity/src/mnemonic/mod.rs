pub mod words;

pub type Entropy = arrayvec::ArrayVec<u8, { MnemonicPhrase::get_entropy_len(24) }>;

use bitvec::field::BitField;
use bitvec::view::BitView;
use core::str::FromStr;
use sha2::Digest;
use zeroize::Zeroize;

type MnemonicInner = arrayvec::ArrayString<{ MnemonicPhrase::get_storage_length_from_count(24) }>;

#[derive(core::clone::Clone, core::fmt::Debug)]
#[derive(core::cmp::Eq, core::cmp::PartialEq, core::cmp::PartialOrd, core::cmp::Ord)]
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct MnemonicPhrase {
    words: MnemonicInner,
    count: usize,
}

impl core::ops::Deref for MnemonicPhrase {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.words.as_str()
    }
}

impl core::convert::TryFrom<&[&str]> for MnemonicPhrase {
    type Error = crate::errors::Error;

    fn try_from(value: &[&str]) -> core::result::Result<Self, Self::Error> {
        let count = value.len();
        let last_index = count - 1;

        if !Self::LEGAL_WORDS_COUNT.contains(&count) {
            return crate::Result::Err(crate::errors::Error::InvalidMnemonicWordsCount);
        }

        let mut words = MnemonicInner::new_const();

        for (index, word) in value.iter().enumerate() {
            if !words::ALL_MNEMONIC_WORDS.contains(word) {
                return crate::Result::Err(crate::errors::Error::InvalidMnemonicWords);
            }

            words.push_str(word);

            if index != last_index {
                words.push(' ');
            }
        }

        crate::Result::Ok(Self {
            words,
            count,
        })
    }
}

impl core::convert::TryFrom<&str> for MnemonicPhrase {
    type Error = crate::errors::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let words_length = value.len();
        let max_words_length = MnemonicInner::new_const().capacity();

        if words_length > max_words_length {
            return crate::Result::Err(crate::errors::Error::InvalidMnemonicWords);
        }

        let mut count = 0;
        let split_str = value.split_whitespace();

        for word in split_str {
            if !words::ALL_MNEMONIC_WORDS.contains(&word) {
                return crate::Result::Err(crate::errors::Error::InvalidMnemonicWords);
            }

            count += 1;
        }

        if !Self::LEGAL_WORDS_COUNT.contains(&count) {
            return crate::Result::Err(crate::errors::Error::InvalidMnemonicWordsCount);
        }

        let words = MnemonicInner::from_str(value).expect("Should be infallible!");

        crate::Result::Ok(Self {
            words,
            count,
        })
    }
}

impl MnemonicPhrase {
    pub const LEGAL_WORDS_COUNT: [usize; 5] = [12, 15, 18, 21, 24];
    pub const LEN_ENTROPY_KDF_ROUND: u32 = 2048;
    pub const LEN_MAX_ENTROPY: usize = Self::get_entropy_len(24);
    pub const LEN_MAX_PASSWORD: usize = 512;
    pub const LEN_SECRET_SEED: usize = 64;
    pub const MNEMONIC_BITS: usize = 11;

    pub const fn get_bit_length(bytes_len: usize) -> usize {
        bytes_len * 8
    }

    pub const fn get_checksum_bit(entropy_len: usize) -> u8 {
        assert!(entropy_len % 4 == 0);
        assert!(entropy_len >= 16);
        assert!(entropy_len <= 32);

        (Self::get_bit_length(entropy_len) / 32) as u8
    }

    pub const fn get_word_count(entropy_len: usize) -> usize {
        (Self::get_bit_length(entropy_len) + Self::get_checksum_bit(entropy_len) as usize)
            / Self::MNEMONIC_BITS
    }

    pub const fn get_storage_length(entropy_len: usize) -> usize {
        let word_count = Self::get_word_count(entropy_len);

        (words::LEN_WORD_MAX * word_count) + word_count - 1
    }

    pub const fn get_entropy_len(word_count: usize) -> usize {
        assert!(word_count % 3 == 0);
        assert!(word_count >= 12);
        assert!(word_count <= 24);

        ((word_count * Self::MNEMONIC_BITS) - (word_count / 3)) / 8
    }

    pub const fn get_storage_length_from_count(word_count: usize) -> usize {
        let entropy_len = Self::get_entropy_len(word_count);

        Self::get_storage_length(entropy_len)
    }

    pub fn generate() -> Self {
        Self::try_generate_with_count(24).expect("Should be infallible!")
    }

    pub fn try_from_entropy(source: &[u8]) -> crate::Result<Self> {
        let entropy_len = source.len();

        if entropy_len % 4 != 0 || !(16..=32).contains(&entropy_len) {
            return crate::Result::Err(crate::errors::Error::InvalidEntropyLength);
        }

        let checksum_bit = 8 - Self::get_checksum_bit(entropy_len);
        let count = Self::get_word_count(entropy_len);
        let last_index = count - 1;
        let mut words = MnemonicInner::new_const();
        let mut entropy_and_checksum = zeroize::Zeroizing::new([0u8; { Self::LEN_MAX_ENTROPY + 1 }]);
        entropy_and_checksum[0..entropy_len].copy_from_slice(source);
        let entropy_ref = &entropy_and_checksum[0..entropy_len];
        let checksum = (sha2::Sha256::digest(entropy_ref)[0] >> checksum_bit) << checksum_bit;
        entropy_and_checksum[entropy_len] = checksum;
        let entropy_ref = &entropy_and_checksum[0..(entropy_len + 1)];

        for (index, slot) in entropy_ref
            .view_bits::<bitvec::prelude::Msb0>()
            .chunks_exact(Self::MNEMONIC_BITS)
            .enumerate()
        {
            let word_indice = slot.load_be::<u16>() as usize;
            words.push_str(words::ALL_MNEMONIC_WORDS[word_indice]);

            if index != last_index {
                words.push(' ');
            }
        }

        crate::Result::Ok(Self {
            words,
            count,
        })
    }

    pub fn try_generate_with_count(word_count: usize) -> crate::Result<Self> {
        if !Self::LEGAL_WORDS_COUNT.contains(&word_count) {
            return crate::Result::Err(crate::errors::Error::InvalidMnemonicWordsCount);
        }

        let entropy_len = Self::get_entropy_len(word_count);
        let mut entropy = zeroize::Zeroizing::new([0u8; Self::LEN_MAX_ENTROPY]);
        getrandom::getrandom(&mut entropy[..]).expect("Catasthropic cryptography failure!");

        Self::try_from_entropy(&entropy[0..entropy_len])
    }

    pub fn get_entropy(&self) -> zeroize::Zeroizing<Entropy> {
        let entropy_len = Self::get_entropy_len(self.count);
        let mut entropy_and_checksum = zeroize::Zeroizing::new([0u8; { Self::LEN_MAX_ENTROPY + 1 }]);
        let entropy_and_checksum_ref_mut = &mut entropy_and_checksum[0..entropy_len + 1];

        let binary_view = entropy_and_checksum_ref_mut
            .view_bits_mut::<bitvec::prelude::Msb0>()
            .chunks_exact_mut(Self::MNEMONIC_BITS);

        for (word, entropy_chunk) in self.words.split_whitespace().zip(binary_view) {
            let word_indice = words::ALL_MNEMONIC_WORDS
                .binary_search(&word)
                .expect("Should be infallible!") as u16;
            entropy_chunk.store_be(word_indice);
        }

        let mut entropy = zeroize::Zeroizing::new(Entropy::default());

        for source_element in &entropy_and_checksum[0..entropy_len] {
            entropy.push(*source_element);
        }

        entropy
    }

    pub fn try_get_secret_seed(
        &self,
        password: &str,
    ) -> crate::Result<zeroize::Zeroizing<[u8; Self::LEN_SECRET_SEED]>> {
        let entropy = self.get_entropy();
        let password_len = password.len();

        if password_len > Self::LEN_MAX_PASSWORD {
            return crate::Result::Err(crate::errors::Error::PasswordTooLong);
        }

        let mut salt = arrayvec::ArrayString::<{ Self::LEN_MAX_PASSWORD + 8 }>::new_const();
        salt.push_str("mnemonic");
        salt.push_str(password);
        let seed = zeroize::Zeroizing::new(pbkdf2::pbkdf2_hmac_array::<
            sha2::Sha512,
            { Self::LEN_SECRET_SEED },
        >(&entropy, salt.as_bytes(), Self::LEN_ENTROPY_KDF_ROUND));
        salt.zeroize();

        crate::Result::Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic, MnemonicType};
    use core::ops::Deref;
    use sp_core::Pair;
    use test_case::test_case;

    const TEST_PASSWORD: &str = "Substrate";

    #[cfg(debug_assertions)]
    const TEST_REPETITIONS: usize = 32;
    #[cfg(not(debug_assertions))]
    const TEST_REPETITIONS: usize = 1024;

    #[test_case::test_case(
        "universe universe universe universe universe universe universe universe universe universe universe universe \
        universe universe universe universe universe universe universe universe universe universe universe universe",
        MnemonicPhrase::get_storage_length_from_count(24) ;
        "longest word is fit perfectly"
    )]
    #[test_case::test_case(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
        47 ;
        "shortest word correctly sized"
    )]
    fn mnemonic_phrase_length_is_correct(mnemonic_word: &str, expected_len: usize) {
        let mnemonic_phrase = MnemonicPhrase::try_from(mnemonic_word).unwrap();

        assert_eq!(mnemonic_phrase.len(), expected_len);
        assert_eq!(mnemonic_phrase.deref(), mnemonic_word);
    }

    #[test_case(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "00000000000000000000000000000000",
        "44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e3\
        3f50c3d5c84fa3e5399c72d6cbbbbc4a49bf76f76d952f479d74655a2ef2d453" ;
        "entropy-12-00"
    )]
    #[test_case(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "4313249608fe8ac10fd5886c92c4579007272cb77c21551ee5b8d60b78041685\
        0f1e26c1f4b8d88ece681cb058ab66d6182bc2ce5a03181f7b74c27576b5c8bf" ;
        "entropy-12-7f"
    )]
    #[test_case(
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "80808080808080808080808080808080",
        "27f3eb595928c60d5bc91a4d747da40ed236328183046892ed6cd5aa9ae38122\
        acd1183adf09a89839acb1e6eaa7fb563cc958a3f9161248d5a036e0d0af533d" ;
        "entropy-12-80"
    )]
    #[test_case(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ffffffffffffffffffffffffffffffff",
        "227d6256fd4f9ccaf06c45eaa4b2345969640462bbb00c5f51f43cb43418c7a7\
        53265f9b1e0c0822c155a9cabc769413ecc14553e135fe140fc50b6722c6b9df" ;
        "entropy-12-ff"
    )]

    fn vectors_from_words_are_correct(phrase: &str, entropy_hex: &str, seed_hex: &str) {
        let expected_entropy = hex::decode(entropy_hex).unwrap();
        let expected_seed = hex::decode(seed_hex).unwrap();

        let mnemonic = MnemonicPhrase::try_from(phrase).unwrap();
        let entropy = mnemonic.get_entropy();
        let seed = mnemonic.try_get_secret_seed(TEST_PASSWORD).unwrap();

        assert_eq!(&entropy[..], &expected_entropy[..]);
        assert_eq!(&seed[..], &expected_seed[..]);
    }

    #[test_case(MnemonicType::Words24 ; "mnemonic-24")]
    #[test_case(MnemonicType::Words21 ; "mnemonic-21")]
    #[test_case(MnemonicType::Words18 ; "mnemonic-18")]
    #[test_case(MnemonicType::Words15 ; "mnemonic-15")]
    #[test_case(MnemonicType::Words12 ; "mnemonic-12")]
    fn tiny_bip39_is_compatible(mtype: MnemonicType) {
        for _ in 0..TEST_REPETITIONS {
            let random_mnemonic = Mnemonic::new(mtype, Language::English).into_phrase();
            let our_mnemonic = MnemonicPhrase::try_from(random_mnemonic.as_str()).unwrap();
            let secret_seed = our_mnemonic.try_get_secret_seed("").unwrap();
            let (substrate_keypair, substrate_secret_seed) =
                sp_core::ed25519::Pair::from_phrase(&random_mnemonic, None).unwrap();
            let keypair_secret_seed = substrate_keypair.seed();

            assert_eq!(&secret_seed[..32], &substrate_secret_seed[..]);
            assert_eq!(&secret_seed[..32], &keypair_secret_seed[..]);
        }
    }

    #[test_case(MnemonicType::Words24 ; "mnemonic-24")]
    #[test_case(MnemonicType::Words21 ; "mnemonic-21")]
    #[test_case(MnemonicType::Words18 ; "mnemonic-18")]
    #[test_case(MnemonicType::Words15 ; "mnemonic-15")]
    #[test_case(MnemonicType::Words12 ; "mnemonic-12")]
    fn tiny_bip39_entropy_is_compatible(mtype: MnemonicType) {
        for _ in 0..TEST_REPETITIONS {
            let random_mnemonic = Mnemonic::new(mtype, Language::English);
            let random_mnemonic_str = random_mnemonic.phrase();
            let random_mnemonic_entropy = random_mnemonic.entropy();
            let our_mnemonic = MnemonicPhrase::try_from_entropy(random_mnemonic_entropy).unwrap();
            let our_mnemonic_str = our_mnemonic.deref();

            assert_eq!(our_mnemonic_str, random_mnemonic_str);
        }
    }

    #[test_case(24 ; "mnemonic-24")]
    #[test_case(21 ; "mnemonic-21")]
    #[test_case(18 ; "mnemonic-18")]
    #[test_case(15 ; "mnemonic-15")]
    #[test_case(12 ; "mnemonic-12")]
    fn substrate_ed25519_is_compatible(word_count: usize) {
        for _ in 0..TEST_REPETITIONS {
            let random_mnemonic = MnemonicPhrase::try_generate_with_count(word_count).unwrap();
            let secret_seed = random_mnemonic.try_get_secret_seed("").unwrap();
            let (substrate_keypair, substrate_secret_seed) =
                sp_core::ed25519::Pair::from_phrase(&random_mnemonic, None).unwrap();
            let keypair_secret_seed = substrate_keypair.seed();

            assert_eq!(&secret_seed[..32], &substrate_secret_seed[..]);
            assert_eq!(&secret_seed[..32], &keypair_secret_seed[..]);
        }
    }
}
