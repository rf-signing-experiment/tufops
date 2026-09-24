//! Signing with an ECDSA P-256 key in the PIV "Digital Signature" slot (9c) of a YubiKey.

use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tuf::crypto::{PublicKey, SignatureScheme};
use tufops_core::backend::Signer;
use x509_cert::der::Encode;
use yubikey::YubiKey;
use yubikey::piv::{self, AlgorithmId, SlotId};
use zeroize::Zeroizing;

pub struct YubiKeySigner {
    yubikey: Mutex<YubiKey>,
    pin: Mutex<Option<Zeroizing<String>>>,
    public: PublicKey,
}

impl YubiKeySigner {
    pub fn open() -> Result<Self> {
        let mut yubikey = YubiKey::open().context("no YubiKey found")?;
        let metadata = piv::metadata(&mut yubikey, SlotId::Signature)
            .context("reading PIV slot 9c (needs YubiKey firmware 5.3 or later)")?;
        let spki = metadata
            .public
            .context("PIV slot 9c has no key")?
            .to_der()?;
        let public = PublicKey::from_spki(&spki, SignatureScheme::EcdsaSha2NistP256)
            .context("PIV slot 9c must hold an ECDSA P-256 key")?;
        Ok(Self {
            yubikey: Mutex::new(yubikey),
            pin: Mutex::default(),
            public,
        })
    }

    /// Sets the PIN used for each signature; slot 9c requires it before every signing operation.
    pub fn set_pin(&self, pin: String) {
        *self.pin.lock().unwrap() = Some(Zeroizing::new(pin));
    }

    pub fn has_pin(&self) -> bool {
        self.pin.lock().unwrap().is_some()
    }
}

#[async_trait]
impl Signer for YubiKeySigner {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut yubikey = self.yubikey.lock().unwrap();
        let pin = self.pin.lock().unwrap();
        match yubikey.verify_pin(pin.as_ref().context("no PIN entered")?.as_bytes()) {
            Err(yubikey::Error::WrongPin { tries }) => bail!("wrong PIN, {tries} tries left"),
            result => result.context("verifying PIN")?,
        }
        let digest = Sha256::digest(msg);
        let signature = piv::sign_data(
            &mut yubikey,
            &digest,
            AlgorithmId::EccP256,
            SlotId::Signature,
        )
        .context("YubiKey signing failed")?;
        Ok(signature.to_vec())
    }
}
