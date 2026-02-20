//  Copyright 2017 Palantir Technologies, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

//! A Serde deserializer which transparently decrypts embedded encrypted strings.
//!
//! Application configurations typically consist mostly of non-sensitive information, with a few
//! bits of information that is sensitive such as authentication secrets or cookie encryption keys.
//! Storing those sensitive values in an encrypted form at rest can defend against leakage when,
//! for example, copy/pasting the config as long as the encryption key is not additionally leaked.
//!
//! # Usage
//!
//! Assume we have a `conf/encrypted-config-value.key` file that looks like:
//!
//! ```not_rust
//! AES:NwQZdNWsFmYMCNSQlfYPDJtFBgPzY8uZlFhMCLnxNQE=
//! ```
//!
//! And a `conf/config.json` file that looks like:
//!
//! ```json
//! {
//!     "secret_value": "${enc:5BBfGvf90H6bApwfxUjNdoKRW1W+GZCbhBuBpzEogVBmQZyWFFxcKyf+UPV5FOhrw/wrVZyoL3npoDfYjPQV/zg0W/P9cVOw}",
//!     "non_secret_value": "hello, world!"
//! }
//! ```
//!
//! ```no_run
//! use serde::Deserialize;
//! use std::fs;
//!
//! #[derive(Deserialize)]
//! struct Config {
//!     secret_value: String,
//!     non_secret_value: String,
//! }
//!
//! let key = "conf/encrypted-config-value.key";
//! let key = serde_encrypted_value::Key::from_file(key)
//!     .unwrap();
//!
//! let config = fs::read("conf/config.json").unwrap();
//!
//! let mut deserializer = serde_json::Deserializer::from_slice(&config);
//! let deserializer = serde_encrypted_value::Deserializer::new(
//!     &mut deserializer, key.as_ref());
//! let config = Config::deserialize(deserializer).unwrap();
//!
//! assert_eq!(config.secret_value, "L/TqOWz7E4z0SoeiTYBrqbqu");
//! assert_eq!(config.non_secret_value, "hello, world!");
//! ```
#![warn(missing_docs, clippy::all)]

pub use crate::deserializer::Deserializer;
use aes_gcm::aes::Aes256;
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use aes_gcm::{AesGcm, Tag};
use base64::display::Base64Display;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::{CryptoRng, RngExt};
use serde::{Deserialize, Serialize};
use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::result;
use std::str::FromStr;
use std::string::FromUtf8Error;
use typenum::U32;

const KEY_PREFIX: &str = "AES:";
const KEY_LEN: usize = 32;
const LEGACY_IV_LEN: usize = 32;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

type LegacyAes256Gcm = AesGcm<Aes256, U32>;

mod deserializer;

/// The reuslt type returned by this library.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
enum ErrorCause {
    AesGcm(aes_gcm::Error),
    Io(io::Error),
    Base64(base64::DecodeError),
    Utf8(FromUtf8Error),
    BadPrefix,
    InvalidLength,
    KeyExhausted,
}

/// The error type returned by this library.
#[derive(Debug)]
pub struct Error(Box<ErrorCause>);

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self.0 {
            ErrorCause::AesGcm(ref e) => fmt::Display::fmt(e, fmt),
            ErrorCause::Io(ref e) => fmt::Display::fmt(e, fmt),
            ErrorCause::Base64(ref e) => fmt::Display::fmt(e, fmt),
            ErrorCause::Utf8(ref e) => fmt::Display::fmt(e, fmt),
            ErrorCause::BadPrefix => fmt.write_str("invalid key prefix"),
            ErrorCause::InvalidLength => fmt.write_str("invalid encrypted value component length"),
            ErrorCause::KeyExhausted => fmt.write_str("key cannot encrypt more than 2^64 values"),
        }
    }
}

impl error::Error for Error {}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum EncryptedValue {
    Aes {
        mode: AesMode,
        #[serde(with = "serde_base64")]
        iv: Vec<u8>,
        #[serde(with = "serde_base64")]
        ciphertext: Vec<u8>,
        #[serde(with = "serde_base64")]
        tag: Vec<u8>,
    },
}

mod serde_base64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::de;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(buf: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        STANDARD.encode(buf).serialize(s)
    }

    pub fn deserialize<'a, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'a>,
    {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(&s)
            .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(&s), &"a base64 string"))
    }
}

// Just some insurance that rand::rng is in fact a CSPRNG
fn secure_rng() -> impl CryptoRng {
    rand::rng()
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AesMode {
    Gcm,
}

/// A marker type indicating that a key can only decrypt values.
pub struct ReadOnly(());

/// A marker type indicating that a key can both encrypt and decrypt values.
pub struct ReadWrite {
    // GCM IVs must never be reused for the same key, and unpredictability makes
    // certain precomputation-based attacks more difficult:
    // https://tools.ietf.org/html/rfc5084#section-4. To account for this, we
    // use basically the same approach as TLSv1.3 - a random nonce generated per
    // key that's XORed with a counter incremented per message:
    // https://tools.ietf.org/html/rfc8446#section-5.3
    iv: [u8; IV_LEN],
    counter: u64,
}

/// A key used to encrypt or decrypt values. It represents both an algorithm and a key.
///
/// Keys which have been deserialized from a string or file cannot encrypt new values; only freshly
/// created keys have that ability. This is indicated by the type parameter `T`.
///
/// The canonical serialized representation of a `Key` is a string consisting of an algorithm
/// identifier, followed by a `:`, followed by the base64 encoded bytes of the key. The `Display`
/// and `FromStr` implementations serialize and deserialize in this format.
///
/// The only algorithm currently supported is AES 256 GCM, which uses the identifier `AES`.
pub struct Key<T> {
    key: [u8; KEY_LEN],
    mode: T,
}

impl Key<ReadWrite> {
    /// Creates a random AES key.
    pub fn random_aes() -> Result<Key<ReadWrite>> {
        Ok(Key {
            key: secure_rng().random(),
            mode: ReadWrite {
                iv: secure_rng().random(),
                counter: 0,
            },
        })
    }

    /// Encrypts a string with this key.
    pub fn encrypt(&mut self, value: &str) -> Result<String> {
        let counter = self.mode.counter;
        self.mode.counter = match self.mode.counter.checked_add(1) {
            Some(v) => v,
            None => return Err(Error(Box::new(ErrorCause::KeyExhausted))),
        };

        let mut iv = Nonce::from(self.mode.iv);
        for (i, byte) in counter.to_le_bytes().iter().enumerate() {
            iv[i] ^= *byte;
        }

        let mut ciphertext = value.as_bytes().to_vec();
        let tag = Aes256Gcm::new(&self.key.into())
            .encrypt_in_place_detached(&iv, &[], &mut ciphertext)
            .map_err(|e| Error(Box::new(ErrorCause::AesGcm(e))))?;

        let value = EncryptedValue::Aes {
            mode: AesMode::Gcm,
            iv: iv.to_vec(),
            ciphertext,
            tag: tag.to_vec(),
        };

        let value = serde_json::to_string(&value).unwrap();
        Ok(STANDARD.encode(value.as_bytes()))
    }
}

impl Key<ReadOnly> {
    /// A convenience function which deserializes a `Key` from a file.
    ///
    /// If the file does not exist, `None` is returned. Otherwise, the contents of the file are
    /// parsed via `Key`'s `FromStr` implementation.
    pub fn from_file<P>(path: P) -> Result<Option<Key<ReadOnly>>>
    where
        P: AsRef<Path>,
    {
        let s = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error(Box::new(ErrorCause::Io(e)))),
        };
        s.parse().map(Some)
    }
}

impl<T> Key<T> {
    /// Decrypts a string with this key.
    pub fn decrypt(&self, value: &str) -> Result<String> {
        let value = STANDARD
            .decode(value)
            .map_err(|e| Error(Box::new(ErrorCause::Base64(e))))?;

        let (iv, mut ct, tag) = match serde_json::from_slice(&value) {
            Ok(EncryptedValue::Aes {
                mode: AesMode::Gcm,
                iv,
                ciphertext,
                tag,
            }) => {
                if iv.len() != IV_LEN || tag.len() != TAG_LEN {
                    return Err(Error(Box::new(ErrorCause::InvalidLength)));
                }

                let mut iv_arr = [0; IV_LEN];
                iv_arr.copy_from_slice(&iv);

                let mut tag_arr = [0; TAG_LEN];
                tag_arr.copy_from_slice(&tag);

                (Iv::Standard(iv_arr), ciphertext, tag_arr)
            }
            Err(_) => {
                if value.len() < LEGACY_IV_LEN + TAG_LEN {
                    return Err(Error(Box::new(ErrorCause::InvalidLength)));
                }

                let mut iv = [0; LEGACY_IV_LEN];
                iv.copy_from_slice(&value[..LEGACY_IV_LEN]);

                let ct = value[LEGACY_IV_LEN..value.len() - TAG_LEN].to_vec();

                let mut tag = [0; TAG_LEN];
                tag.copy_from_slice(&value[value.len() - TAG_LEN..]);

                (Iv::Legacy(iv), ct, tag)
            }
        };

        let tag = Tag::from(tag);

        match iv {
            Iv::Legacy(iv) => {
                let iv = Nonce::from(iv);

                LegacyAes256Gcm::new(&self.key.into())
                    .decrypt_in_place_detached(&iv, &[], &mut ct, &tag)
                    .map_err(|e| Error(Box::new(ErrorCause::AesGcm(e))))?;
            }
            Iv::Standard(iv) => {
                let iv = Nonce::from(iv);

                Aes256Gcm::new(&self.key.into())
                    .decrypt_in_place_detached(&iv, &[], &mut ct, &tag)
                    .map_err(|e| Error(Box::new(ErrorCause::AesGcm(e))))?;
            }
        };

        let pt = String::from_utf8(ct).map_err(|e| Error(Box::new(ErrorCause::Utf8(e))))?;

        Ok(pt)
    }
}

impl<T> fmt::Display for Key<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "AES:{}", Base64Display::new(&self.key, &STANDARD))
    }
}

impl FromStr for Key<ReadOnly> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Key<ReadOnly>> {
        if !s.starts_with(KEY_PREFIX) {
            return Err(Error(Box::new(ErrorCause::BadPrefix)));
        }

        let key = STANDARD
            .decode(&s[KEY_PREFIX.len()..])
            .map_err(|e| Error(Box::new(ErrorCause::Base64(e))))?;

        if key.len() != KEY_LEN {
            return Err(Error(Box::new(ErrorCause::InvalidLength)));
        }

        let mut key_arr = [0; KEY_LEN];
        key_arr.copy_from_slice(&key);

        Ok(Key {
            key: key_arr,
            mode: ReadOnly(()),
        })
    }
}

enum Iv {
    Legacy([u8; LEGACY_IV_LEN]),
    Standard([u8; IV_LEN]),
}

#[cfg(test)]
mod test {
    use serde::Deserialize;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    use super::*;

    const KEY: &str = "AES:NwQZdNWsFmYMCNSQlfYPDJtFBgPzY8uZlFhMCLnxNQE=";

    #[test]
    fn from_file_aes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("encrypted-config-value.key");
        let mut key = File::create(&path).unwrap();
        key.write_all(KEY.as_bytes()).unwrap();

        assert!(Key::from_file(&path).unwrap().is_some());
    }

    #[test]
    fn from_file_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("encrypted-config-value.key");

        assert!(Key::from_file(path).unwrap().is_none());
    }

    #[test]
    fn decrypt_legacy() {
        let ct =
            "5BBfGvf90H6bApwfxUjNdoKRW1W+GZCbhBuBpzEogVBmQZyWFFxcKyf+UPV5FOhrw/wrVZyoL3npoDfYj\
             PQV/zg0W/P9cVOw";
        let pt = "L/TqOWz7E4z0SoeiTYBrqbqu";

        let key = KEY.parse::<Key<ReadOnly>>().unwrap();
        let actual = key.decrypt(ct).unwrap();
        assert_eq!(actual, pt);
    }

    #[test]
    fn decrypt() {
        let ct =
            "eyJ0eXBlIjoiQUVTIiwibW9kZSI6IkdDTSIsIml2IjoiUCtRQXM5aHo4VFJVOUpNLyIsImNpcGhlcnRle\
             HQiOiJmUGpDaDVuMkR0cklPSVNXSklLcVQzSUtRNUtONVI3LyIsInRhZyI6ImlJRFIzYUtER1UyK1Brej\
             NPSEdSL0E9PSJ9";
        let pt = "L/TqOWz7E4z0SoeiTYBrqbqu";

        let key = KEY.parse::<Key<ReadOnly>>().unwrap();
        let actual = key.decrypt(ct).unwrap();
        assert_eq!(actual, pt);
    }

    #[test]
    fn encrypt_decrypt() {
        let mut key = Key::random_aes().unwrap();
        let pt = "L/TqOWz7E4z0SoeiTYBrqbqu";
        let ct = key.encrypt(pt).unwrap();
        let actual = key.decrypt(&ct).unwrap();
        assert_eq!(pt, actual);
    }

    #[test]
    fn unique_ivs() {
        let mut key = Key::random_aes().unwrap();
        let pt = "L/TqOWz7E4z0SoeiTYBrqbqu";
        let ct1 = key.encrypt(pt).unwrap();
        let ct2 = key.encrypt(pt).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn deserializer() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Config {
            sub: Subconfig,
        }

        #[derive(Deserialize, PartialEq, Debug)]
        struct Subconfig {
            encrypted: Vec<String>,
            plaintext: String,
        }

        let config = r#"
{
    "sub": {
        "encrypted": [
            "${enc:5BBfGvf90H6bApwfxUjNdoKRW1W+GZCbhBuBpzEogVBmQZyWFFxcKyf+UPV5FOhrw/wrVZyoL3npoDfYjPQV/zg0W/P9cVOw}"
        ],
        "plaintext": "${foobar}"
    }
}
        "#;

        let key = KEY.parse().unwrap();
        let mut deserializer = serde_json::Deserializer::from_str(config);
        let deserializer = Deserializer::new(&mut deserializer, Some(&key));

        let config = Config::deserialize(deserializer).unwrap();

        let expected = Config {
            sub: Subconfig {
                encrypted: vec!["L/TqOWz7E4z0SoeiTYBrqbqu".to_string()],
                plaintext: "${foobar}".to_string(),
            },
        };

        assert_eq!(config, expected);
    }
}
