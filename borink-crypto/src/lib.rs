use ::aead::arrayvec::ArrayVec;
use aes_gcm_siv::{self as aead, aead::{Aead, AeadInPlace}, Aes256GcmSiv, AesGcmSiv, KeyInit};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use generic_array::{self, arr, GenericArray};
use core::fmt::Debug;
use std::ops::Add;
use thiserror::Error;
// use tracing::debug;
// use ed25519_compact::{self as ed};

// #[derive(Clone)]
// pub struct Key {
//     kp: ed::KeyPair,
// }

// impl Key {
//     pub fn to_public_key(&self) -> PublicKey {
//         let pk = self.kp.pk;

//         PublicKey { pk }
//     }
// }

// #[derive(Clone)]
// pub struct PublicKey {
//     pk: ed::PublicKey,
// }

// pub fn create_key() -> Key {
//     let kp = ed::KeyPair::generate();

//     Key { kp }
// }

// pub struct SavedPublicKey(String);

// impl SavedPublicKey {
//     pub fn validate_pem(public_key_pem: &str) -> Result<Self, KeyError> {
//         let key = load_public_key(public_key_pem)?;

//         Ok(save_public_key(&key))
//     }

//     pub fn pem(self) -> String {
//         self.0
//     }
// }

// pub fn save_public_key(key: &PublicKey) -> SavedPublicKey {
//     SavedPublicKey(key.pk.to_pem())
// }

// pub fn save_private_key(key: &Key) -> String {
//     key.kp.sk.to_pem()
// }

#[derive(Error, Debug)]
pub enum KeyError {
    // #[error("Failed to parse string as PKCS8-PEM-encoded Ed25519 private key.")]
    // Ed25519Private,
    // #[error("Failed to parse string as SubjectPublicKeyInfo-PEM-encoded Ed25519 public key.")]
    // Ed25519Public,
    #[error("Failed to parse bytes as 256-bit symmetric key.")]
    SymmetricBytes,
}

// pub fn load_key(private_key_pem: &str) -> Result<Key, KeyError> {
//     // The PEM file contains only the seed, so public key is recomputed and we don't have to validate it
//     let sk = ed::SecretKey::from_pem(private_key_pem).map_err(|_| KeyError::Ed25519Private)?;
//     let pk = sk.public_key();
//     let kp = ed::KeyPair { pk, sk };
//     Ok(Key { kp })
// }

// pub fn load_public_key(public_key_pem: &str) -> Result<PublicKey, KeyError> {
//     let pk = ed::PublicKey::from_pem(public_key_pem).map_err(|_| KeyError::Ed25519Public)?;
//     Ok(PublicKey { pk })
// }

// pub fn sign_data(key: &Key, data: &[u8]) -> Vec<u8> {
//     let signature = key.kp.sk.sign(data, Some(ed::Noise::generate()));

//     signature.to_vec()
// }

// pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &PublicKey) -> bool {
//     match &ed::Signature::from_slice(signature) {
//         Ok(sig) => public_key.pk.verify(data, sig).is_ok(),
//         Err(_) => false,
//     }
// }

pub fn create_symmetric_key(rng: &mut (impl RngCore + CryptoRng)) -> SymmetricKey {
    let mut key_bytes = [0u8; 32];

    rng.fill_bytes(&mut key_bytes);

    SymmetricKey {
        key_256: key_bytes.into(),
    }
}

#[derive(Clone, PartialEq)]
pub struct SymmetricKey {
    key_256: aead::Key<aead::Aes256GcmSiv>,
}

impl Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = debug_secret_bytes(self.raw_bytes());

        f.debug_tuple("SymmetricKey")
            .field(&format!("sha256={}...", hex))
            .finish()
    }
}

impl AsSymmetricKey for SymmetricKey {
    fn as_symmetric_key(&self) -> &SymmetricKey {
        self
    }
}

impl SymmetricKey {
    pub fn raw_bytes(&self) -> &[u8] {
        self.key_256.as_slice()
    }

    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 32 {
            return Err(KeyError::SymmetricBytes);
        }

        Ok(SymmetricKey {
            key_256: aead::Key::<aead::Aes256GcmSiv>::clone_from_slice(bytes),
        })
    }

    pub fn derive_key(base_secret: [u8; 32], key: u64) -> Self {
        let mut rng = ChaCha20Rng::from_seed(base_secret);
        rng.set_stream(key);

        create_symmetric_key(&mut rng)
    }
}

pub fn debug_secret_bytes(bytes: &[u8]) -> String {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let hex: String = result[0..4]
        .iter()
        .map(|b| format!("{:02x?}", b).to_string())
        .collect();

    hex
}

struct Encrypted<const N: usize> {

}

use generic_array::{ArrayLength, IntoArrayLength, ConstArrayLength};
use typenum::{bit::B1, Const, Sum, ToUInt, UInt, UTerm, Unsigned, U, U1, U16,};


struct Base<const N: usize>;
trait AddTo { type Added; }

impl<const N: usize> AddTo
    for Base<N>
where
    Const<N>: IntoArrayLength,
    ConstArrayLength<N>: Add<U16> + ArrayLength
{
    type Added = Sum<ConstArrayLength<N>, U16>;
}

type WithTag<N> = Sum<N, U16>;
type F<const N: usize> = <Base<N> as AddTo>::Added;

struct Tagged<const N: usize> where
    Const<N>: ToUInt + IntoArrayLength,
    U<N>: Add<U16> + ArrayLength,
    WithTag<U<N>>: ArrayLength,
    // WithTag<U<N>>::ArrayType<u8>: ConstDefault
{
    tagged: GenericArray<u8, WithTag<U<N>>>
}

// pub fn z<const N: usize>(data: GenericArray<u8, ConstArrayLength<N>>) -> [u8; N] where
//     Const<N>: IntoArrayLength
// {
//     let b = data.into_array();

//     b
// }

// pub fn z<const M: usize, N: ArrayLength>(data: GenericArray<u8, N>) -> [u8; M] where
//     Const<M>: IntoArrayLength
// {
//     let b = data.into_array();

//     b
// }

// pub fn z<const N: usize>(data: [u8; N]) -> [u8; N] where
//     Const<N>: IntoArrayLength
// {
//     let b = data.into_array();

//     b
// }

pub fn symmetric_encrypt_const<const N: usize>(
    data: &[u8; N],
    // key: &impl AsSymmetricKey,
    // rng: &mut (impl RngCore + CryptoRng),
) -> GenericArray<u8, WithTag<U<N>>> where
    Const<N>: ToUInt + IntoArrayLength,
    U<N>: Add<U16> + ArrayLength,
    WithTag<U<N>>: ArrayLength,
{
    let arr: Tagged<N> = Tagged {
        tagged: GenericArray::default()
    };
    todo!();


    // let cipher = aead::Aes256GcmSiv::new(&key.as_symmetric_key().key_256);

    // let mut iv_bytes = vec![0u8; 12];
    // rng.fill_bytes(&mut iv_bytes);

    // let nonce = aead::Nonce::from_slice(&iv_bytes);

    // let buffer = arr![1; U6]; 

    // // Tag is appended at the end
    // let mut ciphertext = cipher.encrypt_in_place(nonce, session_data).unwrap();

    // // We put the nonce at the end
    // ciphertext.append(&mut iv_bytes);

    // ciphertext

    // Ok(())

    todo!()
}



pub fn symmetric_encrypt_inner<const IN: usize, const OUT: usize>(
    data: &[u8; IN],
    associated_data: &[u8],
    key: &impl AsSymmetricKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> [u8; OUT] {
    let cipher = aead::Aes256GcmSiv::new(&key.as_symmetric_key().key_256);

    let mut buffer = arrayvec::ArrayVec::<u8, OUT>::new();

    // Copy session data into the buffer
    buffer.try_extend_from_slice(data.as_slice()).unwrap();

    let mut iv_bytes = [0u8; 12];
    rng.fill_bytes(&mut iv_bytes);

    let nonce = aead::Nonce::from_slice(&iv_bytes);

    // Perform encryption in place
    cipher.encrypt_in_place(nonce, associated_data, &mut buffer).unwrap();

    buffer.try_extend_from_slice(&iv_bytes).unwrap();

    buffer.into_inner().unwrap()
}

pub use paste;

// Append nonce at the end
    // buffer[$size..$size + 12].copy_from_slice(&iv_bytes);
#[macro_export]
macro_rules! generate_symmetric_encrypt {
    ($($size:literal),*) => {
        $(
        $crate::paste::paste! {
            pub fn [<symmetric_encrypt_ $size>] (
                data: &[u8; $size],
                associated_data: &[u8],
                key: &impl $crate::AsSymmetricKey,
                rng: &mut (impl rand::RngCore + rand::CryptoRng),
            ) -> [u8; $size + 28] {
                $crate::symmetric_encrypt_inner(data, associated_data, key, rng)
            }
        }
        )*
    };
}

pub fn symmetric_encrypt(
    session_data: &[u8],
    key: &impl AsSymmetricKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    let cipher = aead::Aes256GcmSiv::new(&key.as_symmetric_key().key_256);

    let mut iv_bytes = vec![0u8; 12];
    rng.fill_bytes(&mut iv_bytes);

    let nonce = aead::Nonce::from_slice(&iv_bytes);

    // Tag is appended at the end
    let mut ciphertext = cipher.encrypt(nonce, session_data).unwrap();

    // We put the nonce at the end
    ciphertext.append(&mut iv_bytes);

    ciphertext
}

/// The decryption failed. This can be due to tampered data, an invalid key, invalid IV or incorrect tag.
#[derive(Error, Debug)]
#[error("Decryption failed.")]
pub struct DecryptFailed;

pub trait AsSymmetricKey {
    fn as_symmetric_key(&self) -> &SymmetricKey;
}

/// Keys should be passed in the order that they should be tried
pub fn symmetric_decrypt(
    encrypted: &[u8],
    keys: &[impl AsSymmetricKey],
) -> Result<Vec<u8>, DecryptFailed> {
    let encrypted_len = encrypted.len();

    // nonce of 12 bytes, tag of 16 bytes
    if encrypted_len < 28 {
        return Err(DecryptFailed);
    }

    let iv = encrypted
        .get((encrypted_len - 12)..(encrypted_len))
        .unwrap();
    let nonce = aead::Nonce::from_slice(iv);
    let ciphertext = encrypted.get(0..(encrypted_len - 12)).unwrap();

    for key in keys {
        let cipher = aead::Aes256GcmSiv::new(&key.as_symmetric_key().key_256);

        if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext) {
            return Ok(decrypted);
        }
    }
    // debug!(
    //     "Failed to decrypt with keys: {:?}",
    //     keys.iter()
    //         .map(|k| k.as_symmetric_key())
    //         .collect::<Vec<_>>()
    // );

    Err(DecryptFailed)
}

pub fn symmetric_decrypt_new(
    encrypted: &[u8; 36],
    keys: &[impl AsSymmetricKey],
) -> Result<[u8; 8], DecryptFailed> {
    let encrypted_len = encrypted.len();

    let iv = encrypted
        .get((encrypted_len - 12)..(encrypted_len))
        .unwrap();
    let nonce = aead::Nonce::from_slice(iv);

    for key in keys {
        let cipher = aead::Aes256GcmSiv::new(&key.as_symmetric_key().key_256);

        let mut buffer = arrayvec::ArrayVec::<u8, 24>::new();
        buffer.try_extend_from_slice(&encrypted[..24]).unwrap();

        if cipher.decrypt_in_place(nonce, &[], &mut buffer).is_ok() {
            let decrypted = buffer[0..8].try_into().unwrap();

            return Ok(decrypted);
        }
    }

    // debug!(
    //     "Failed to decrypt with keys: {:?}",
    //     keys.iter()
    //         .map(|k| k.as_symmetric_key())
    //         .collect::<Vec<_>>()
    // );

    Err(DecryptFailed)
}

pub fn symmetric_decrypt_inner<const IN: usize, const T: usize, const OUT: usize>(
    encrypted: &[u8; IN],
    associated_data: &[u8],
    keys: &[impl AsSymmetricKey],
) -> Result<[u8; OUT], DecryptFailed> {
    let iv = encrypted
        .get(T..)
        .unwrap();
    let nonce = aead::Nonce::from_slice(iv);

    for key in keys {
        let cipher = aead::Aes256GcmSiv::new(&key.as_symmetric_key().key_256);

        let mut buffer = arrayvec::ArrayVec::<u8, T>::new();
        buffer.try_extend_from_slice(&encrypted[..T]).unwrap();

        if cipher.decrypt_in_place(nonce, associated_data, &mut buffer).is_ok() {
            let decrypted = buffer[0..OUT].try_into().unwrap();

            return Ok(decrypted);
        }
    }

    // debug!(
    //     "Failed to decrypt with keys: {:?}",
    //     keys.iter()
    //         .map(|k| k.as_symmetric_key())
    //         .collect::<Vec<_>>()
    // );

    Err(DecryptFailed)
}

#[macro_export]
macro_rules! generate_symmetric_decrypt {
    ($($size:expr),*) => {
        $(
        $crate::paste::paste! {
            pub fn [<symmetric_decrypt_ $size>] (
                encrypted: &[u8; $size + 16 + 12],
                associated_data: &[u8],
                keys: &[impl $crate::AsSymmetricKey],
            ) -> Result<[u8; $size], $crate::DecryptFailed> {
                $crate::symmetric_decrypt_inner::<{$size + 28}, {$size + 16}, $size>(encrypted, associated_data, keys)
            }
        }
        )*
    };
}

#[cfg(test)]
mod tests {

    use rand::{
        rngs::{OsRng, StdRng},
        Rng,
    };

    use super::*;

    // #[test]
    // fn generate_key_length() {
    //     let key = create_key();

    //     let raw_private = key.kp.sk.as_slice();

    //     // Ed25519 private should be 32 bytes, but it also includes public key so 64 bytes
    //     assert_eq!(raw_private.len(), 64);

    //     let raw_public = key.kp.pk.as_slice();

    //     // Ed25519 public should be 32 bytes
    //     assert_eq!(raw_public.len(), 32);
    // }

    // #[test]
    // fn save_load_key() {
    //     let key = create_key();

    //     let saved_key = save_private_key(&key);

    //     let loaded_key = load_key(&saved_key).unwrap();

    //     assert_eq!(key.kp, loaded_key.kp);
    // }

    // #[test]
    // fn sign_verify_data() {
    //     let key = create_key();

    //     let data = b"some_data";

    //     let signature = sign_data(&key, data);

    //     assert!(verify_signature(
    //         data,
    //         signature.as_slice(),
    //         &key.to_public_key()
    //     ))
    // }

    // #[test]
    // fn sign_invalid_data() {
    //     let key = create_key();

    //     let data = b"some_data";

    //     let signature = sign_data(&key, data);

    //     assert!(!verify_signature(
    //         b"other_data",
    //         signature.as_slice(),
    //         &key.to_public_key()
    //     ))
    // }

    // #[test]
    // fn sign_invalid_sig() {
    //     let key = create_key();

    //     let data = b"some_data";

    //     assert!(!verify_signature(data, b"bad_sig", &key.to_public_key()))
    // }

    // #[test]
    // fn sign_invalid_pub_key() {
    //     let key = create_key();

    //     let data = b"some_data";

    //     let signature = sign_data(&key, data);

    //     let other_key = create_key().to_public_key();

    //     assert!(!verify_signature(data, &signature, &other_key))
    // }

    generate_symmetric_encrypt!(8, 32);
    generate_symmetric_decrypt!(8);

    #[test]
    fn encrypt_decrypt_in_place() {
        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        let key = create_symmetric_key(&mut rng);
        
        let some_bytes: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

        let encrypted: [u8; 36] = symmetric_encrypt_8(&some_bytes, &[], &key, &mut rng);

        let data_decrypt = symmetric_decrypt_8(&encrypted, &[], &[key]).unwrap();

        assert_eq!(some_bytes.as_slice(), &data_decrypt);
    }

    
    #[test]
    fn encrypt_decrypt() {
        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        let key = create_symmetric_key(&mut rng);

        let data = "this_is_some_amount_of_data_that_I_encrypt";
        

        let encrypted = symmetric_encrypt(data.as_bytes(), &key, &mut rng);

        let data_decrypt = symmetric_decrypt(&encrypted, &[key]).unwrap();

        assert_eq!(data.as_bytes(), data_decrypt);
    }

    #[test]
    fn encrypt_decrypt_different() {
        let mut seed = [0u8; 32];
        OsRng.fill(&mut seed);
        let mut rng = StdRng::from_seed(seed);

        let key = create_symmetric_key(&mut rng);

        let data = "this_is_some_amount_of_data_that_I_encrypt";

        let encrypted = symmetric_encrypt(data.as_bytes(), &key, &mut rng);

        let mut encrypted_tampered = encrypted.clone();
        let mut encrypted_invalid_iv = encrypted.clone();
        let mut encrypted_bad_tag = encrypted.clone();

        if encrypted_tampered[0] != 3 {
            encrypted_tampered[0] = 3
        } else {
            encrypted_tampered[0] = 2;
        }

        let encrypted_len = encrypted.len();

        if encrypted_invalid_iv[encrypted_len - 1] != 3 {
            encrypted_invalid_iv[encrypted_len - 1] = 3
        } else {
            encrypted_invalid_iv[encrypted_len - 1] = 2;
        }

        if encrypted_bad_tag[encrypted_len - 20] != 3 {
            encrypted_bad_tag[encrypted_len - 20] = 3
        } else {
            encrypted_bad_tag[encrypted_len - 20] = 2;
        }

        let tampered_decrypt = symmetric_decrypt(&encrypted_tampered, &[key.clone()]);
        let invalid_iv_decrypt = symmetric_decrypt(&encrypted_invalid_iv, &[key.clone()]);
        let bad_tag_decrypt = symmetric_decrypt(&encrypted_bad_tag, &[key]);

        assert!(tampered_decrypt.is_err());
        assert!(invalid_iv_decrypt.is_err());
        assert!(bad_tag_decrypt.is_err());
    }
}
