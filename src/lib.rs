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
//! extern crate serde;
//! extern crate serde_json;
//! extern crate serde_encrypted_value;
//!
//! #[macro_use]
//! extern crate serde_derive;
//!
//! use serde::Deserialize;
//! use std::io::Read;
//! use std::fs::File;
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
//!     let mut config = vec![];
//!     File::open("conf/config.json")
//!         .unwrap()
//!         .read_to_end(&mut config)
//!         .unwrap();
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
#![warn(missing_docs)]
#![doc(html_root_url="https://docs.rs/serde-encrypted-value/0.1.1")]

extern crate base64;
extern crate openssl;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
extern crate tempdir;

use openssl::symm::{self, Cipher};
use openssl::rand::rand_bytes;
use serde::{ser, de, Serialize, Deserialize};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::result::Result as StdResult;
use std::str::FromStr;

use errors::*;

pub use deserializer::Deserializer;

const KEY_PREFIX: &'static str = "AES:";
const KEY_LEN: usize = 32;
const LEGACY_IV_LEN: usize = 32;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

mod deserializer;

/// Errors
pub mod errors {
    error_chain!{}
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum EncryptedValue {
    #[serde(rename = "AES")]
    Aes {
        mode: AesMode,
        #[serde(serialize_with = "base64_serialize", deserialize_with = "base64_deserialize")]
        iv: Vec<u8>,
        #[serde(serialize_with = "base64_serialize", deserialize_with = "base64_deserialize")]
        ciphertext: Vec<u8>,
        #[serde(serialize_with = "base64_serialize", deserialize_with = "base64_deserialize")]
        tag: Vec<u8>,
    },
}

fn base64_serialize<S>(buf: &Vec<u8>, s: S) -> StdResult<S::Ok, S::Error>
    where S: ser::Serializer
{
    base64::encode(buf).serialize(s)
}

fn base64_deserialize<D>(d: D) -> StdResult<Vec<u8>, D::Error>
    where D: de::Deserializer
{
    let s = String::deserialize(d)?;
    base64::decode(&s).map_err(|_| {
                                   de::Error::invalid_value(de::Unexpected::Str(&s),
                                                            &"a base64 string")
                               })
}

#[derive(Serialize, Deserialize)]
enum AesMode {
    #[serde(rename = "GCM")]
    Gcm,
}

/// A key used to encrypt or decrypt values. It represents both an algorithm and a key.
///
/// The canonical serialized representation of a `Key` is a string consisting of an algorithm
/// identifier, followed by a `:`, followed by the base64 encoded bytes of the key. The `Display`
/// and `FromStr` implementations serialize and deserialize in this format.
///
/// The only algorithm currently supported is AES 256 GCM, which uses the identifier `AES`.
pub struct Key(Vec<u8>);

impl Key {
    /// Creates a random AES key.
    pub fn random_aes() -> Result<Key> {
        let mut key = vec![0; KEY_LEN];
        rand_bytes(&mut key)
            .chain_err(|| "error generating random key")?;
        Ok(Key(key))
    }

    /// A convenience function which deserializes a `Key` from a file.
    ///
    /// If the file does not exist, `None` is returned. Otherwise, the contents of the file are
    /// parsed via `Key`'s `FromStr` implementation.
    pub fn from_file<P>(path: P) -> Result<Option<Key>>
        where P: AsRef<Path>
    {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                // FIXME ew :(
                Err(e).chain_err(|| "error opening key")?;
                unreachable!();
            }
        };
        let mut s = String::new();
        file.read_to_string(&mut s)
            .chain_err(|| "error reading key")?;
        s.parse().map(Some)
    }

    /// Encrypts a string with this key.
    pub fn encrypt(&self, value: &str) -> Result<String> {
        let mut iv = vec![0; IV_LEN];
        rand_bytes(&mut iv)
            .chain_err(|| "error generating nonce")?;

        let mut tag = vec![0; TAG_LEN];

        let cipher = Cipher::aes_256_gcm();
        let ct = symm::encrypt_aead(cipher, &self.0, Some(&iv), &[], value.as_bytes(), &mut tag)
            .chain_err(|| "error encrypting value")?;

        let value = EncryptedValue::Aes {
            mode: AesMode::Gcm,
            iv: iv,
            ciphertext: ct,
            tag: tag,
        };

        let value = serde_json::to_string(&value).unwrap();
        Ok(base64::encode(value.as_bytes()))
    }

    /// Decrypts a string with this key.
    pub fn decrypt(&self, value: &str) -> Result<String> {
        let value = base64::decode(&value)
            .chain_err(|| "error decoding encrypted value")?;

        let (iv, ct, tag)= match serde_json::from_slice(&value) {
            Ok(EncryptedValue::Aes { mode: AesMode::Gcm, iv, ciphertext, tag }) => {
                (iv, ciphertext, tag)
            }
            Err(_) => {
                if value.len() < LEGACY_IV_LEN + TAG_LEN {
                    bail!("encrypted value too short");
                }

                let (iv, value) = value.split_at(LEGACY_IV_LEN);
                let (ct, tag) = value.split_at(value.len() - TAG_LEN);

                (iv.to_vec(), ct.to_vec(), tag.to_vec())
            }
        };

        let cipher = Cipher::aes_256_gcm();
        let pt = symm::decrypt_aead(cipher, &self.0, Some(&iv), &[], &ct, &tag)
            .chain_err(|| "error decrypting value")?;
        let pt = String::from_utf8(pt)
            .chain_err(|| "error decrypting value")?;

        Ok(pt)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "AES:{}", base64::encode(&self.0))
    }
}

impl FromStr for Key {
    type Err = Error;

    fn from_str(s: &str) -> Result<Key> {
        if !s.starts_with(KEY_PREFIX) {
            bail!("invalid key prefix");
        }

        let key = base64::decode(&s[KEY_PREFIX.len()..])
            .chain_err(|| "error decoding key")?;
        Ok(Key(key))
    }
}

#[cfg(test)]
mod test {
    use serde::Deserialize;
    use tempdir::TempDir;
    use std::fs::File;
    use std::io::Write;

    use super::*;

    const KEY: &'static str = "AES:NwQZdNWsFmYMCNSQlfYPDJtFBgPzY8uZlFhMCLnxNQE=";

    #[test]
    fn from_file_aes() {
        let dir = TempDir::new("from_file_aes").unwrap();
        let path = dir.path().join("encrypted-config-value.key");
        let mut key = File::create(&path).unwrap();
        key.write_all(KEY.as_bytes()).unwrap();

        assert!(Key::from_file(&path).unwrap().is_some());
    }

    #[test]
    fn from_file_empty() {
        let dir = TempDir::new("from_file_aes").unwrap();
        let path = dir.path().join("encrypted-config-value.key");

        assert!(Key::from_file(&path).unwrap().is_none());
    }

    #[test]
    fn decrypt_legacy() {
        let ct = "5BBfGvf90H6bApwfxUjNdoKRW1W+GZCbhBuBpzEogVBmQZyWFFxcKyf+UPV5FOhrw/wrVZyoL3npoDfYj\
                  PQV/zg0W/P9cVOw";
        let pt = "L/TqOWz7E4z0SoeiTYBrqbqu";

        let key: Key = KEY.parse().unwrap();
        let actual = key.decrypt(ct).unwrap();
        assert_eq!(actual, pt);
    }

    #[test]
    fn decrypt() {
        let ct = "eyJ0eXBlIjoiQUVTIiwibW9kZSI6IkdDTSIsIml2IjoiUCtRQXM5aHo4VFJVOUpNLyIsImNpcGhlcnRle\
                  HQiOiJmUGpDaDVuMkR0cklPSVNXSklLcVQzSUtRNUtONVI3LyIsInRhZyI6ImlJRFIzYUtER1UyK1Brej\
                  NPSEdSL0E9PSJ9";
        let pt = "L/TqOWz7E4z0SoeiTYBrqbqu";

        let key: Key = KEY.parse().unwrap();
        let actual = key.decrypt(ct).unwrap();
        assert_eq!(actual, pt);
    }

    #[test]
    fn encrypt_decrypt() {
        let key: Key = Key::random_aes().unwrap();
        let pt = "L/TqOWz7E4z0SoeiTYBrqbqu";
        let ct = key.encrypt(pt).unwrap();
        let actual = key.decrypt(&ct).unwrap();
        assert_eq!(pt, actual);
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
