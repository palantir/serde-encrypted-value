// Copyright 2017 Palantir Technologies, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use serde::de;
use std::fmt;

use Key;

/// A deserializer which automatically decrypts strings.
///
/// Encrypted strings should be formatted like `${enc:<base64 ciphertext here>}`.
pub struct Deserializer<'a, D> {
    deserializer: D,
    key: Option<&'a Key>,
}

impl<'a, D> Deserializer<'a, D>
    where D: de::Deserializer
{
    /// Creates a new `Deserializer` wrapping another deserializer and decrypting string values.
    ///
    /// If `key` is `None`, deserialization will fail if an encrypted string is encountered.
    pub fn new(deserializer: D, key: Option<&'a Key>) -> Deserializer<'a, D> {
        Deserializer {
            deserializer: deserializer,
            key: key,
        }
    }
}

macro_rules! forward_deserialize {
    ($name:ident) => {forward_deserialize!($name, );};
    ($name:ident, $($arg:tt => $ty:ty),*) => {
        fn $name<V>(self, $($arg: $ty,)* visitor: V) -> Result<V::Value, D::Error>
            where V: de::Visitor
        {
            let visitor = Visitor {
                visitor: visitor,
                key: self.key,
            };
            self.deserializer.$name($($arg,)* visitor)
        }
    }
}

impl<'a, D> de::Deserializer for Deserializer<'a, D>
    where D: de::Deserializer
{
    type Error = D::Error;

    forward_deserialize!(deserialize);
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
    forward_deserialize!(deserialize_seq_fixed_size, len => usize);
    forward_deserialize!(deserialize_bytes);
    forward_deserialize!(deserialize_byte_buf);
    forward_deserialize!(deserialize_map);
    forward_deserialize!(deserialize_unit_struct, name => &'static str);
    forward_deserialize!(deserialize_newtype_struct, name => &'static str);
    forward_deserialize!(deserialize_tuple_struct, name => &'static str, len => usize);
    forward_deserialize!(deserialize_struct,
                         name => &'static str,
                         fields => &'static [&'static str]);
    forward_deserialize!(deserialize_struct_field);
    forward_deserialize!(deserialize_tuple, len => usize);
    forward_deserialize!(deserialize_enum,
                         name => &'static str,
                         variants => &'static [&'static str]);
    forward_deserialize!(deserialize_ignored_any);
}

struct Visitor<'a, V> {
    visitor: V,
    key: Option<&'a Key>,
}

impl<'a, V> Visitor<'a, V> {
    fn expand_str<E>(&self, s: &str) -> Result<Option<String>, E>
        where E: de::Error
    {
        if s.starts_with("${enc:") && s.ends_with("}") {
            match self.key {
                Some(key) => {
                    match key.decrypt(&s[6..s.len() - 1]) {
                        Ok(s) => Ok(Some(s)),
                        Err(e) => Err(E::custom(&e.to_string())),
                    }
                }
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

impl<'a, V> de::Visitor for Visitor<'a, V>
    where V: de::Visitor
{
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
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
        where E: de::Error
    {
        match self.expand_str(v)? {
            Some(s) => self.visitor.visit_string(s),
            None => self.visitor.visit_str(v),
        }
    }

    fn visit_string<E>(self, v: String) -> Result<V::Value, E>
        where E: de::Error
    {
        match self.expand_str(&v)? {
            Some(s) => self.visitor.visit_string(s),
            None => self.visitor.visit_string(v),
        }
    }

    fn visit_unit<E>(self) -> Result<V::Value, E>
        where E: de::Error
    {
        self.visitor.visit_unit()
    }

    fn visit_none<E>(self) -> Result<V::Value, E>
        where E: de::Error
    {
        self.visitor.visit_none()
    }

    fn visit_some<D>(self, deserializer: D) -> Result<V::Value, D::Error>
        where D: de::Deserializer
    {
        let deserializer = Deserializer::new(deserializer, self.key);
        self.visitor.visit_some(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<V::Value, D::Error>
        where D: de::Deserializer
    {
        let deserializer = Deserializer::new(deserializer, self.key);
        self.visitor.visit_newtype_struct(deserializer)
    }

    fn visit_seq<V2>(self, visitor: V2) -> Result<V::Value, V2::Error>
        where V2: de::SeqVisitor
    {
        let visitor = Visitor {
            visitor: visitor,
            key: self.key,
        };
        self.visitor.visit_seq(visitor)
    }

    fn visit_map<V2>(self, visitor: V2) -> Result<V::Value, V2::Error>
        where V2: de::MapVisitor
    {
        let visitor = Visitor {
            visitor: visitor,
            key: self.key,
        };
        self.visitor.visit_map(visitor)
    }

    fn visit_enum<V2>(self, visitor: V2) -> Result<V::Value, V2::Error>
        where V2: de::EnumVisitor
    {
        let visitor = Visitor {
            visitor: visitor,
            key: self.key,
        };
        self.visitor.visit_enum(visitor)
    }
}

impl<'a, V> de::SeqVisitor for Visitor<'a, V>
    where V: de::SeqVisitor
{
    type Error = V::Error;

    fn visit_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, V::Error>
        where T: de::DeserializeSeed
    {
        let seed = DeserializeSeed {
            seed: seed,
            key: self.key,
        };
        self.visitor.visit_seed(seed)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.visitor.size_hint()
    }
}

impl<'a, V> de::MapVisitor for Visitor<'a, V>
    where V: de::MapVisitor
{
    type Error = V::Error;

    fn visit_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, V::Error>
        where K: de::DeserializeSeed
    {
        let seed = DeserializeSeed {
            seed: seed,
            key: self.key,
        };
        self.visitor.visit_key_seed(seed)
    }

    fn visit_value_seed<T>(&mut self, seed: T) -> Result<T::Value, V::Error>
        where T: de::DeserializeSeed
    {
        let seed = DeserializeSeed {
            seed: seed,
            key: self.key,
        };
        self.visitor.visit_value_seed(seed)
    }

    fn visit_seed<K, T>(&mut self,
                        kseed: K,
                        vseed: T)
                        -> Result<Option<(K::Value, T::Value)>, V::Error>
        where K: de::DeserializeSeed,
              T: de::DeserializeSeed
    {
        let kseed = DeserializeSeed {
            seed: kseed,
            key: self.key,
        };
        let vseed = DeserializeSeed {
            seed: vseed,
            key: self.key,
        };
        self.visitor.visit_seed(kseed, vseed)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.visitor.size_hint()
    }
}

impl<'a, V> de::EnumVisitor for Visitor<'a, V>
    where V: de::EnumVisitor
{
    type Error = V::Error;
    type Variant = Visitor<'a, V::Variant>;

    fn visit_variant_seed<T>(self, seed: T) -> Result<(T::Value, Visitor<'a, V::Variant>), V::Error>
        where T: de::DeserializeSeed
    {
        let seed = DeserializeSeed {
            seed: seed,
            key: self.key,
        };
        match self.visitor.visit_variant_seed(seed) {
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

impl<'a, V> de::VariantVisitor for Visitor<'a, V>
    where V: de::VariantVisitor
{
    type Error = V::Error;

    fn visit_unit(self) -> Result<(), V::Error> {
        self.visitor.visit_unit()
    }

    fn visit_newtype_seed<T>(self, seed: T) -> Result<T::Value, V::Error>
        where T: de::DeserializeSeed
    {
        let seed = DeserializeSeed {
            seed: seed,
            key: self.key,
        };
        self.visitor.visit_newtype_seed(seed)
    }

    fn visit_tuple<V2>(self, len: usize, visitor: V2) -> Result<V2::Value, V::Error>
        where V2: de::Visitor
    {
        let visitor = Visitor {
            visitor: visitor,
            key: self.key,
        };
        self.visitor.visit_tuple(len, visitor)
    }

    fn visit_struct<V2>(self,
                        fields: &'static [&'static str],
                        visitor: V2)
                        -> Result<V2::Value, V::Error>
        where V2: de::Visitor
    {
        let visitor = Visitor {
            visitor: visitor,
            key: self.key,
        };
        self.visitor.visit_struct(fields, visitor)
    }
}

struct DeserializeSeed<'a, T> {
    seed: T,
    key: Option<&'a Key>,
}

impl<'a, T> de::DeserializeSeed for DeserializeSeed<'a, T>
    where T: de::DeserializeSeed
{
    type Value = T::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<T::Value, D::Error>
        where D: de::Deserializer
    {
        let deserializer = Deserializer::new(deserializer, self.key);
        self.seed.deserialize(deserializer)
    }
}
