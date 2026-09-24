//! Google Cloud: KMS for online keys, Cloud Storage for publishing.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::Digest;
use google_cloud_storage::client::{Storage, StorageControl};
use sha2::{Digest as _, Sha256};
use tuf::crypto::{KeyType, PublicKey, SignatureScheme};
use tufops_core::backend::{BlobStore, Signer};
use url::Url;

/// An `EC_SIGN_P256_SHA256` Cloud KMS key version.
pub struct KmsSigner {
    client: KeyManagementService,
    name: String,
    public: PublicKey,
}

impl KmsSigner {
    pub async fn new(name: &str) -> Result<Self> {
        let client = KeyManagementService::builder().build().await?;
        let key = client.get_public_key().set_name(name).send().await?;
        let public =
            PublicKey::from_pem(&key.pem, KeyType::Ecdsa, SignatureScheme::EcdsaSha2NistP256)
                .with_context(|| format!("{name} is not an ECDSA P-256 key"))?;
        Ok(Self {
            client,
            name: name.to_owned(),
            public,
        })
    }
}

#[async_trait]
impl Signer for KmsSigner {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let digest = Digest::new().set_sha256(Bytes::copy_from_slice(&Sha256::digest(msg)));
        let response = self
            .client
            .asymmetric_sign()
            .set_name(&self.name)
            .set_digest(digest)
            .send()
            .await;
        Ok(response
            .with_context(|| format!("signing with {}", self.name))?
            .signature
            .to_vec())
    }
}

/// A Cloud Storage bucket, optionally under a prefix.
pub struct Gcs {
    storage: Storage,
    control: StorageControl,
    bucket: String,
    prefix: String,
    /// Public URL of the objects under `prefix`.
    public: Url,
}

impl Gcs {
    /// `path` is `bucket` or `bucket/prefix`.
    pub async fn new(path: &str) -> Result<Self> {
        let (bucket, prefix) = path.split_once('/').unwrap_or((path, ""));
        let prefix = prefix.trim_matches('/');
        Ok(Self {
            public: public_base(bucket, prefix)?,
            storage: Storage::builder().build().await?,
            control: StorageControl::builder().build().await?,
            bucket: format!("projects/_/buckets/{bucket}"),
            prefix: if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/")
            },
        })
    }
}

/// The public URL of `bucket`'s objects under `prefix`.
fn public_base(bucket: &str, prefix: &str) -> Result<Url> {
    let mut url = Url::parse("https://storage.googleapis.com/")?;
    extend_path(&mut url, std::iter::once(bucket).chain(prefix.split('/')));
    Ok(url)
}

/// Appends path segments to `url`, percent-encoding each and skipping empty ones.
fn extend_path<'a>(url: &mut Url, segments: impl Iterator<Item = &'a str>) {
    let mut path = url.path_segments_mut().expect("https URLs have paths");
    path.extend(segments.filter(|s| !s.is_empty()));
}

#[async_trait]
impl BlobStore for Gcs {
    async fn list(&self, prefix: &str) -> Result<HashMap<String, Vec<u8>>> {
        let mut objects = HashMap::new();
        let mut token = String::new();
        loop {
            let page = (self.control.list_objects())
                .set_parent(&self.bucket)
                .set_prefix(format!("{}{prefix}", self.prefix))
                .set_page_token(token)
                .send()
                .await?;
            for object in page.objects {
                let name = object
                    .name
                    .strip_prefix(&self.prefix)
                    .unwrap_or(&object.name)
                    .to_owned();
                objects.insert(
                    name,
                    object
                        .checksums
                        .map(|c| c.md5_hash.to_vec())
                        .unwrap_or_default(),
                );
            }
            if page.next_page_token.is_empty() {
                return Ok(objects);
            }
            token = page.next_page_token;
        }
    }

    async fn put(&self, name: &str, data: Vec<u8>) -> Result<()> {
        let object = format!("{}{name}", self.prefix);
        (self
            .storage
            .write_object(&self.bucket, object, Bytes::from(data)))
        .set_cache_control("no-cache")
        .set_content_type(if name.ends_with(".json") {
            "application/json"
        } else {
            "application/octet-stream"
        })
        .send_unbuffered()
        .await?;
        Ok(())
    }

    async fn put_file(&self, name: &str, path: &Path) -> Result<()> {
        let file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("opening {path:?}"))?;
        let object = format!("{}{name}", self.prefix);
        self.storage
            .write_object(&self.bucket, object, file)
            .send_unbuffered()
            .await?;
        Ok(())
    }

    fn public_url(&self, name: &str) -> String {
        let mut url = self.public.clone();
        extend_path(&mut url, name.split('/'));
        url.into()
    }
}
