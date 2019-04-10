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
//! fn main() {
//!     let key = "conf/encrypted-config-value.key";
//!     let key = serde_encrypted_value::Key::from_file(key)
//!         .unwrap();
//!
//!     let config = fs::read("conf/config.json").unwrap();
//!
//!     let mut deserializer = serde_json::Deserializer::from_slice(&config);
//!     let deserializer = serde_encrypted_value::Deserializer::new(
//!         &mut deserializer, key.as_ref());
//!     let config = Config::deserialize(deserializer).unwrap();
//!
//!     assert_eq!(config.secret_value, "L/TqOWz7E4z0SoeiTYBrqbqu");
//!     assert_eq!(config.non_secret_value, "hello, world!");
//! }
//! ```
#![warn(missing_docs, clippy::all)]
#![doc(html_root_url = "https://docs.rs/serde-encrypted-value/0.4")]

use openssl::error::ErrorStack;
use openssl::rand::rand_bytes;
use openssl::symm::{self, Cipher};
use serde::{Deserialize, Serialize};
use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::result;
use std::str::FromStr;
use std::string::FromUtf8Error;

pub use crate::deserializer::Deserializer;

const KEY_PREFIX: &str = "AES:";
const KEY_LEN: usize = 32;
const LEGACY_IV_LEN: usize = 32;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

mod deserializer;

/// The reuslt type returned by this library.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
enum ErrorCause {
    Openssl(ErrorStack),
    Io(io::Error),
    Base64(base64::DecodeError),
    Utf8(FromUtf8Error),
    BadPrefix,
    TooShort,
    KeyExhausted,
}

/// The error type returned by this library.
#[derive(Debug)]
pub struct Error(Box<ErrorCause>);

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self.0 {
            ErrorCause::Openssl(ref e) => fmt::Display::fmt(e, fmt),
            ErrorCause::Io(ref e) => fmt::Display::fmt(e, fmt),
            ErrorCause::Base64(ref e) => fmt::Display::fmt(e, fmt),
            ErrorCause::Utf8(ref e) => fmt::Display::fmt(e, fmt),
            ErrorCause::BadPrefix => fmt.write_str("invalid key prefix"),
            ErrorCause::TooShort => fmt.write_str("encrypted value too short"),
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
    use base64;
    use serde::de;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(buf: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64::encode(buf).serialize(s)
    }

    pub fn deserialize<'a, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'a>,
    {
        let s = String::deserialize(d)?;
        base64::decode(&s)
            .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(&s), &"a base64 string"))
    }
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
    // IVs are actually 12 bytes, but 8 is more than enough and easier to increment.
    iv: u64,
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
    key: Vec<u8>,
    mode: T,
}

impl Key<ReadWrite> {
    /// Creates a random AES key.
    pub fn random_aes() -> Result<Key<ReadWrite>> {
        let mut key = vec![0; KEY_LEN];
        rand_bytes(&mut key).map_err(|e| Error(Box::new(ErrorCause::Openssl(e))))?;

        Ok(Key {
            key,
            mode: ReadWrite { iv: 0 },
        })
    }

    /// Encrypts a string with this key.
    pub fn encrypt(&mut self, value: &str) -> Result<String> {
        let iv_num = self.mode.iv;
        self.mode.iv = match self.mode.iv.checked_add(1) {
            Some(v) => v,
            None => return Err(Error(Box::new(ErrorCause::KeyExhausted))),
        };

        let mut iv = vec![0; IV_LEN];
        iv[..8].copy_from_slice(&iv_num.to_le_bytes());

        let mut tag = vec![0; TAG_LEN];

        let cipher = Cipher::aes_256_gcm();
        let ciphertext = symm::encrypt_aead(
            cipher,
            &self.key,
            Some(&iv),
            &[],
            value.as_bytes(),
            &mut tag,
        )
        .map_err(|e| Error(Box::new(ErrorCause::Openssl(e))))?;

        let value = EncryptedValue::Aes {
            mode: AesMode::Gcm,
            iv,
            ciphertext,
            tag,
        };

        let value = serde_json::to_string(&value).unwrap();
        Ok(base64::encode(value.as_bytes()))
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
        let value = base64::decode(&value).map_err(|e| Error(Box::new(ErrorCause::Base64(e))))?;

        let (iv, ct, tag) = match serde_json::from_slice(&value) {
            Ok(EncryptedValue::Aes {
                mode: AesMode::Gcm,
                iv,
                ciphertext,
                tag,
            }) => (iv, ciphertext, tag),
            Err(_) => {
                if value.len() < LEGACY_IV_LEN + TAG_LEN {
                    return Err(Error(Box::new(ErrorCause::TooShort)));
                }

                let (iv, value) = value.split_at(LEGACY_IV_LEN);
                let (ct, tag) = value.split_at(value.len() - TAG_LEN);

                (iv.to_vec(), ct.to_vec(), tag.to_vec())
            }
        };

        let cipher = Cipher::aes_256_gcm();
        let pt = symm::decrypt_aead(cipher, &self.key, Some(&iv), &[], &ct, &tag)
            .map_err(|e| Error(Box::new(ErrorCause::Openssl(e))))?;
        let pt = String::from_utf8(pt).map_err(|e| Error(Box::new(ErrorCause::Utf8(e))))?;

        Ok(pt)
    }
}

impl<T> fmt::Display for Key<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "AES:{}", base64::encode(&self.key))
    }
}

impl FromStr for Key<ReadOnly> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Key<ReadOnly>> {
        if !s.starts_with(KEY_PREFIX) {
            return Err(Error(Box::new(ErrorCause::BadPrefix)));
        }

        let key = base64::decode(&s[KEY_PREFIX.len()..])
            .map_err(|e| Error(Box::new(ErrorCause::Base64(e))))?;

        Ok(Key {
            key,
            mode: ReadOnly(()),
        })
    }
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

        assert!(Key::from_file(&path).unwrap().is_none());
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
