use crate::protocol::{digest, Digest, HASH_WIDTH_IN_BYTES};
use anyhow::{anyhow, bail, Context, Result};

pub const TOKEN_HASH_PREFIX: &str = "sha256:";

pub fn hash_token(token: &str) -> String {
    format!(
        "{}{}",
        TOKEN_HASH_PREFIX,
        hex::encode(digest(token.as_bytes()))
    )
}

pub fn parse_token_hash(value: &str) -> Result<Digest> {
    let value = value.strip_prefix(TOKEN_HASH_PREFIX).unwrap_or(value);
    let bytes = hex::decode(value).with_context(|| "invalid token_hash hex")?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "token_hash must be {} bytes, got {}",
            HASH_WIDTH_IN_BYTES,
            bytes.len()
        )
    })
}

pub fn response_for_token(token: &str, nonce: &Digest) -> Digest {
    let token_hash = digest(token.as_bytes());
    response_for_token_hash(&token_hash, nonce)
}

pub fn response_for_token_hash(token_hash: &Digest, nonce: &Digest) -> Digest {
    digest_pair(token_hash, nonce)
}

pub fn legacy_response_for_token(token: &str, nonce: &Digest) -> Digest {
    digest_pair(token.as_bytes(), nonce)
}

fn digest_pair(left: &[u8], right: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha256};

    Sha256::new()
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

pub fn validate_token_hash(value: &str) -> Result<()> {
    parse_token_hash(value).map(|_| ()).or_else(|err| {
        bail!("{err:#}. Generate a relay token hash with `rathole --hash-token <token>`")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_roundtrips() -> Result<()> {
        let encoded = hash_token("secret");
        let parsed = parse_token_hash(&encoded)?;
        assert_eq!(
            parse_token_hash(encoded.trim_start_matches(TOKEN_HASH_PREFIX))?,
            parsed
        );
        Ok(())
    }

    #[test]
    fn token_response_matches_hash_response() -> Result<()> {
        let nonce = [7u8; HASH_WIDTH_IN_BYTES];
        let token_hash = parse_token_hash(&hash_token("secret"))?;
        assert_eq!(
            response_for_token("secret", &nonce),
            response_for_token_hash(&token_hash, &nonce)
        );
        assert_ne!(
            response_for_token("wrong", &nonce),
            response_for_token_hash(&token_hash, &nonce)
        );
        Ok(())
    }

    #[test]
    fn legacy_response_matches_original_concat() {
        let nonce = [9u8; HASH_WIDTH_IN_BYTES];
        let mut bytes = Vec::from("secret".as_bytes());
        bytes.extend_from_slice(&nonce);

        assert_eq!(legacy_response_for_token("secret", &nonce), digest(&bytes));
    }
}
