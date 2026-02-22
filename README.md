<p align="right">
<a href="https://autorelease.general.dmz.palantir.tech/palantir/serde-encrypted-value"><img src="https://img.shields.io/badge/Perform%20an-Autorelease-success.svg" alt="Autorelease"></a>
</p>

# serde-encrypted-value

[Documentation](https://docs.rs/serde-encrypted-value)

Serde deserializer which transparently decrypts embedded encrypted strings.

Application configurations typically consist mostly of non-sensitive information, with a few
bits of information that is sensitive such as authentication secrets or cookie encryption keys.
Storing those sensitive values in an encrypted form at rest can defend against leakage when,
for example, copy/pasting the config as long as the encryption key is not additionally leaked.

It is compatible with https://github.com/palantir/encrypted-config-value, though unlike that
library, serde-encrypted-value does not support RSA.

## Usage

Assume we have a `conf/encrypted-config-value.key` file that looks like:

```
AES:NwQZdNWsFmYMCNSQlfYPDJtFBgPzY8uZlFhMCLnxNQE=
```

And a `conf/config.json` file that looks like:

```json
{
    "secret_value": "${enc:5BBfGvf90H6bApwfxUjNdoKRW1W+GZCbhBuBpzEogVBmQZyWFFxcKyf+UPV5FOhrw/wrVZyoL3npoDfYjPQV/zg0W/P9cVOw}",
    "non_secret_value": "hello, world!"
}
```

```rust
extern crate serde;
extern crate serde_json;
extern crate serde_encrypted_value;

#[macro_use]
extern crate serde_derive;

use serde::Deserialize;
use std::io::Read;
use std::fs::File;

#[derive(Deserialize)]
struct Config {
    secret_value: String,
    non_secret_value: String,
}

fn main() {
    let key = "conf/encrypted-config-value.key";
    let key = serde_encrypted_value::Key::from_file(key)
        .unwrap();

    let mut config = vec![];
    File::open("conf/config.json")
        .unwrap()
        .read_to_end(&mut config)
        .unwrap();

    let mut deserializer = serde_json::Deserializer::from_slice(&config);
    let deserializer = serde_encrypted_value::Deserializer::new(
        &mut deserializer, key.as_ref());
    let config = Config::deserialize(deserializer).unwrap();

    assert_eq!(config.secret_value, "L/TqOWz7E4z0SoeiTYBrqbqu");
    assert_eq!(config.non_secret_value, "hello, world!");
}
```

## License

This repository is made available under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
