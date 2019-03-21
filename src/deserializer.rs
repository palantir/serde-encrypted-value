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

use serde::de;
use std::fmt;

use crate::Key;

/// A deserializer which automatically decrypts strings.
///
/// Encrypted strings should be formatted like `${enc:<base64 ciphertext here>}`.
pub struct Deserializer<'a, D, T> {
    deserializer: D,
    key: Option<&'a Key<T>>,
}

impl<'a, 'de, D, T> Deserializer<'a, D, T>
where
    D: de::Deserializer<'de>,
{
    /// Creates a new `Deserializer` wrapping another deserializer and decrypting string values.
    ///
    /// If `key` is `None`, deserialization will fail if an encrypted string is encountered.
    pub fn new(deserializer: D, key: Option<&'a Key<T>>) -> Deserializer<'a, D, T> {
        Deserializer { deserializer, key }
    }
}

macro_rules! forward_deserialize {
    ($name:ident) => {forward_deserialize!($name, );};
    ($name:ident, $($arg:tt => $ty:ty),*) => {
        fn $name<V>(self, $($arg: $ty,)* visitor: V) -> Result<V::Value, D::Error>
            where V: de::Visitor<'de>
        {
            let visitor = Visitor {
                visitor: visitor,
                key: self.key,
            };
            self.deserializer.$name($($arg,)* visitor)
        }
    }
}

impl<'a, 'de, D, T> de::Deserializer<'de> for Deserializer<'a, D, T>
where
    D: de::Deserializer<'de>,
{
    type Error = D::Error;

    forward_deserialize!(deserialize_any);
    forward_deserialize!(deserialize_bool);
    forward_deserialize!(deserialize_u8);
    forward_deserialize!(deserialize_u16);
    forward_deserialize!(deserialize_u32);
    forward_deserialize!(deserialize_u64);
    forward_deserialize!(deserialize_i8);
    forward_deserialize!(deserialize_i16);
    forward_deserialize!(deserialize_i32);
    forward_deserialize!(deserialize_i64);
    forward_deserialize!(deserialize_f32);
    forward_deserialize!(deserialize_f64);
    forward_deserialize!(deserialize_char);
    forward_deserialize!(deserialize_str);
    forward_deserialize!(deserialize_string);
    forward_deserialize!(deserialize_unit);
    forward_deserialize!(deserialize_option);
    forward_deserialize!(deserialize_seq);
    forward_deserialize!(deserialize_bytes);
    forward_deserialize!(deserialize_byte_buf);
    forward_deserialize!(deserialize_map);
    forward_deserialize!(deserialize_unit_struct, name => &'static str);
    forward_deserialize!(deserialize_newtype_struct, name => &'static str);
    forward_deserialize!(deserialize_tuple_struct, name => &'static str, len => usize);
    forward_deserialize!(deserialize_struct,
                         name => &'static str,
                         fields => &'static [&'static str]);
    forward_deserialize!(deserialize_identifier);
    forward_deserialize!(deserialize_tuple, len => usize);
    forward_deserialize!(deserialize_enum,
                         name => &'static str,
                         variants => &'static [&'static str]);
    forward_deserialize!(deserialize_ignored_any);
}

struct Visitor<'a, V, T> {
    visitor: V,
    key: Option<&'a Key<T>>,
}

impl<'a, V, T> Visitor<'a, V, T> {
    fn expand_str<E>(&self, s: &str) -> Result<Option<String>, E>
    where
        E: de::Error,
    {
        if s.starts_with("${enc:") && s.ends_with('}') {
            match self.key {
                Some(key) => match key.decrypt(&s[6..s.len() - 1]) {
                    Ok(s) => Ok(Some(s)),
                    Err(e) => Err(E::custom(&e.to_string())),
                },
                None => Err(E::custom("missing encryption key")),
            }
        } else {
            Ok(None)
        }
    }
}

macro_rules! forward_visit {
    ($name:ident, $ty:ty) => {
        fn $name<E>(self, v: $ty) -> Result<V::Value, E>
            where E: de::Error
        {
            self.visitor.$name(v)
        }
    }
}

impl<'a, 'de, V, T> de::Visitor<'de> for Visitor<'a, V, T>
where
    V: de::Visitor<'de>,
{
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.visitor.expecting(formatter)
    }

    forward_visit!(visit_bool, bool);
    forward_visit!(visit_i8, i8);
    forward_visit!(visit_i16, i16);
    forward_visit!(visit_i32, i32);
    forward_visit!(visit_i64, i64);
    forward_visit!(visit_u8, u8);
    forward_visit!(visit_u16, u16);
    forward_visit!(visit_u32, u32);
    forward_visit!(visit_u64, u64);
    forward_visit!(visit_f32, f32);
    forward_visit!(visit_f64, f64);
    forward_visit!(visit_char, char);
    forward_visit!(visit_bytes, &[u8]);
    forward_visit!(visit_byte_buf, Vec<u8>);

    fn visit_str<E>(self, v: &str) -> Result<V::Value, E>
    where
        E: de::Error,
    {
        match self.expand_str(v)? {
            Some(s) => self.visitor.visit_string(s),
            None => self.visitor.visit_str(v),
        }
    }

    fn visit_string<E>(self, v: String) -> Result<V::Value, E>
    where
        E: de::Error,
    {
        match self.expand_str(&v)? {
            Some(s) => self.visitor.visit_string(s),
            None => self.visitor.visit_string(v),
        }
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<V::Value, E>
    where
        E: de::Error,
    {
        match self.expand_str(v)? {
            Some(s) => self.visitor.visit_string(s),
            None => self.visitor.visit_borrowed_str(v),
        }
    }

    fn visit_unit<E>(self) -> Result<V::Value, E>
    where
        E: de::Error,
    {
        self.visitor.visit_unit()
    }

    fn visit_none<E>(self) -> Result<V::Value, E>
    where
        E: de::Error,
    {
        self.visitor.visit_none()
    }

    fn visit_some<D>(self, deserializer: D) -> Result<V::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let deserializer = Deserializer::new(deserializer, self.key);
        self.visitor.visit_some(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<V::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let deserializer = Deserializer::new(deserializer, self.key);
        self.visitor.visit_newtype_struct(deserializer)
    }

    fn visit_seq<V2>(self, visitor: V2) -> Result<V::Value, V2::Error>
    where
        V2: de::SeqAccess<'de>,
    {
        let visitor = Visitor {
            visitor,
            key: self.key,
        };
        self.visitor.visit_seq(visitor)
    }

    fn visit_map<V2>(self, visitor: V2) -> Result<V::Value, V2::Error>
    where
        V2: de::MapAccess<'de>,
    {
        let visitor = Visitor {
            visitor,
            key: self.key,
        };
        self.visitor.visit_map(visitor)
    }

    fn visit_enum<V2>(self, visitor: V2) -> Result<V::Value, V2::Error>
    where
        V2: de::EnumAccess<'de>,
    {
        let visitor = Visitor {
            visitor,
            key: self.key,
        };
        self.visitor.visit_enum(visitor)
    }
}

impl<'a, 'de, V, T> de::SeqAccess<'de> for Visitor<'a, V, T>
where
    V: de::SeqAccess<'de>,
{
    type Error = V::Error;

    fn next_element_seed<S>(&mut self, seed: S) -> Result<Option<S::Value>, V::Error>
    where
        S: de::DeserializeSeed<'de>,
    {
        let seed = DeserializeSeed {
            seed,
            key: self.key,
        };
        self.visitor.next_element_seed(seed)
    }

    fn size_hint(&self) -> Option<usize> {
        self.visitor.size_hint()
    }
}

impl<'a, 'de, V, T> de::MapAccess<'de> for Visitor<'a, V, T>
where
    V: de::MapAccess<'de>,
{
    type Error = V::Error;

    fn next_key_seed<S>(&mut self, seed: S) -> Result<Option<S::Value>, V::Error>
    where
        S: de::DeserializeSeed<'de>,
    {
        let seed = DeserializeSeed {
            seed,
            key: self.key,
        };
        self.visitor.next_key_seed(seed)
    }

    fn next_value_seed<S>(&mut self, seed: S) -> Result<S::Value, V::Error>
    where
        S: de::DeserializeSeed<'de>,
    {
        let seed = DeserializeSeed {
            seed,
            key: self.key,
        };
        self.visitor.next_value_seed(seed)
    }

    #[allow(clippy::type_complexity)]
    fn next_entry_seed<K, V2>(
        &mut self,
        kseed: K,
        vseed: V2,
    ) -> Result<Option<(K::Value, V2::Value)>, V::Error>
    where
        K: de::DeserializeSeed<'de>,
        V2: de::DeserializeSeed<'de>,
    {
        let kseed = DeserializeSeed {
            seed: kseed,
            key: self.key,
        };
        let vseed = DeserializeSeed {
            seed: vseed,
            key: self.key,
        };
        self.visitor.next_entry_seed(kseed, vseed)
    }

    fn size_hint(&self) -> Option<usize> {
        self.visitor.size_hint()
    }
}

impl<'a, 'de, V, T> de::EnumAccess<'de> for Visitor<'a, V, T>
where
    V: de::EnumAccess<'de>,
{
    type Error = V::Error;
    type Variant = Visitor<'a, V::Variant, T>;

    #[allow(clippy::type_complexity)]
    fn variant_seed<S>(self, seed: S) -> Result<(S::Value, Visitor<'a, V::Variant, T>), V::Error>
    where
        S: de::DeserializeSeed<'de>,
    {
        let seed = DeserializeSeed {
            seed,
            key: self.key,
        };
        match self.visitor.variant_seed(seed) {
            Ok((value, variant)) => {
                let variant = Visitor {
                    visitor: variant,
                    key: self.key,
                };
                Ok((value, variant))
            }
            Err(e) => Err(e),
        }
    }
}

impl<'a, 'de, V, T> de::VariantAccess<'de> for Visitor<'a, V, T>
where
    V: de::VariantAccess<'de>,
{
    type Error = V::Error;

    fn unit_variant(self) -> Result<(), V::Error> {
        self.visitor.unit_variant()
    }

    fn newtype_variant_seed<S>(self, seed: S) -> Result<S::Value, V::Error>
    where
        S: de::DeserializeSeed<'de>,
    {
        let seed = DeserializeSeed {
            seed,
            key: self.key,
        };
        self.visitor.newtype_variant_seed(seed)
    }

    fn tuple_variant<V2>(self, len: usize, visitor: V2) -> Result<V2::Value, V::Error>
    where
        V2: de::Visitor<'de>,
    {
        let visitor = Visitor {
            visitor,
            key: self.key,
        };
        self.visitor.tuple_variant(len, visitor)
    }

    fn struct_variant<V2>(
        self,
        fields: &'static [&'static str],
        visitor: V2,
    ) -> Result<V2::Value, V::Error>
    where
        V2: de::Visitor<'de>,
    {
        let visitor = Visitor {
            visitor,
            key: self.key,
        };
        self.visitor.struct_variant(fields, visitor)
    }
}

struct DeserializeSeed<'a, S, T> {
    seed: S,
    key: Option<&'a Key<T>>,
}

impl<'a, 'de, S, T> de::DeserializeSeed<'de> for DeserializeSeed<'a, S, T>
where
    S: de::DeserializeSeed<'de>,
{
    type Value = S::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<S::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let deserializer = Deserializer::new(deserializer, self.key);
        self.seed.deserialize(deserializer)
    }
}
