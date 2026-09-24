//! Interfaces to the services that hold keys and published files, so the cloud provider can be
//! swapped out.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use tuf::crypto::PublicKey;

/// A private key that signs TUF metadata.
#[async_trait]
pub trait Signer: Send + Sync {
    fn public_key(&self) -> &PublicKey;

    /// Signs `msg`, returning the signature in the encoding TUF uses for the key's scheme.
    async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

/// Object storage the repository is published to. Names are relative to the storage root.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Objects whose names start with `prefix`, with the MD5 digest of each.
    async fn list(&self, prefix: &str) -> Result<HashMap<String, Vec<u8>>>;

    /// Writes a small object that changes over time, so it must not be cached.
    async fn put(&self, name: &str, data: Vec<u8>) -> Result<()>;

    /// Uploads a local file as an object that never changes once written.
    async fn put_file(&self, name: &str, path: &Path) -> Result<()>;

    /// The public HTTPS URL clients download object `name` from.
    fn public_url(&self, name: &str) -> String;
}
