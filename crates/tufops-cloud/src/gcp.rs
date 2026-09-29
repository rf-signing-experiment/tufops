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
use tracing::debug;
use tuf::crypto::PublicKey;
use tufops_core::backend::{BlobStore, Signer, public_key_from_pem};
use url::Url;

/// An `EC_SIGN_P256_SHA256` Cloud KMS key version.
pub struct KmsSigner {
    client: KeyManagementService,
    name: String,
    public: PublicKey,
}

impl KmsSigner {
    pub async fn new(name: &str) -> Result<Self> {
        debug!("fetching the public key of Cloud KMS key {name}");
        let client = KeyManagementService::builder().build().await?;
        let key = client.get_public_key().set_name(name).send().await?;
        let public = public_key_from_pem(&key.pem)
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
        debug!(bucket, prefix, "opening Cloud Storage");
        let storage_url = Url::parse("https://storage.googleapis.com/")?;
        Ok(Self {
            public: with_path(storage_url, &format!("{bucket}/{prefix}")),
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

    /// The full name of object `name`, under the prefix.
    fn object(&self, name: &str) -> String {
        format!("{}{name}", self.prefix)
    }
}

/// `url` with the segments of `path` appended, each percent-encoded, skipping empty ones.
fn with_path(mut url: Url, path: &str) -> Url {
    (url.path_segments_mut().expect("https URLs have paths"))
        .extend(path.split('/').filter(|s| !s.is_empty()));
    url
}

#[async_trait]
impl BlobStore for Gcs {
    async fn list(&self, prefix: &str) -> Result<HashMap<String, Vec<u8>>> {
        let mut objects = HashMap::new();
        let mut token = String::new();
        loop {
            let page = (self.control.list_objects())
                .set_parent(&self.bucket)
                .set_prefix(self.object(prefix))
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
                debug!(prefix, count = objects.len(), "listed objects");
                return Ok(objects);
            }
            token = page.next_page_token;
        }
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let read = self.storage.read_object(&self.bucket, self.object(name));
        let mut response = match read.send().await {
            Err(err) if err.http_status_code() == Some(404) => return Ok(None),
            response => response?,
        };
        let mut data = vec![];
        while let Some(chunk) = response.next().await.transpose()? {
            data.extend_from_slice(&chunk);
        }
        Ok(Some(data))
    }

    async fn put(&self, name: &str, data: Vec<u8>) -> Result<()> {
        debug!(name, bytes = data.len(), "uploading");
        (self.storage)
            .write_object(&self.bucket, self.object(name), Bytes::from(data))
            .set_cache_control("no-cache")
            .set_content_type(if name.ends_with(".json") {
                "application/json"
            } else if name.ends_with(".html") {
                "text/html; charset=utf-8"
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
        self.storage
            .write_object(&self.bucket, self.object(name), file)
            .send_unbuffered()
            .await?;
        Ok(())
    }

    fn public_url(&self, name: &str) -> String {
        with_path(self.public.clone(), name).into()
    }
}
