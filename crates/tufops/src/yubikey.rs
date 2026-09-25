//! Signing with an ECDSA P-256 key in the PIV "Digital Signature" slot (9c) of a YubiKey.

use std::io::IsTerminal;
use std::sync::Mutex;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use dialoguer::Select;
use sha2::{Digest, Sha256};
use tuf::crypto::{PublicKey, SignatureScheme};
use tufops_core::backend::Signer;
use x509_cert::der::Encode;
use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::reader::Context as Readers;
use yubikey::{Serial, YubiKey};
use zeroize::Zeroizing;

pub struct YubiKeySigner {
    yubikey: Mutex<YubiKey>,
    pin: Mutex<Option<Zeroizing<String>>>,
    public: PublicKey,
}

impl YubiKeySigner {
    /// Opens the YubiKey with serial number `device`, or else the only one plugged in. With
    /// several plugged in, asks which to use.
    pub fn open(device: Option<u32>) -> Result<Self> {
        let serial = match device {
            Some(serial) => serial,
            None => choose()?,
        };
        let mut yubikey = YubiKey::open_by_serial(Serial(serial))
            .with_context(|| format!("no YubiKey with serial number {serial} found"))?;
        let metadata = match piv::metadata(&mut yubikey, SlotId::Signature) {
            Err(yubikey::Error::NotSupported) => {
                bail!("YubiKey {serial} is too old: tufops needs firmware 5.3 or later")
            }
            // What the YubiKey answers when the slot is empty.
            Err(yubikey::Error::GenericError) => {
                bail!("YubiKey {serial} has no key in PIV slot 9c")
            }
            result => result.with_context(|| format!("YubiKey {serial}: reading PIV slot 9c"))?,
        };
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

/// The serial number of the YubiKey to use: the only one plugged in, or the one the user picks.
fn choose() -> Result<u32> {
    let mut readers = Readers::open().context("no YubiKey found")?;
    let found: Vec<_> = readers
        .iter()?
        .filter_map(|reader| reader.open().ok())
        .map(|yubikey| {
            (
                yubikey.serial().0,
                format!("{} ({})", yubikey.serial(), yubikey.name()),
            )
        })
        .collect();
    match found.as_slice() {
        [] => bail!("no YubiKey found"),
        [(serial, _)] => Ok(*serial),
        _ => {
            ensure!(
                std::io::stdin().is_terminal(),
                "{} YubiKeys are plugged in: pick one with --device <serial number>",
                found.len()
            );
            let names: Vec<_> = found.iter().map(|(_, name)| name).collect();
            let chosen = Select::new()
                .with_prompt("Which YubiKey?")
                .items(&names)
                .default(0)
                .interact()?;
            Ok(found[chosen].0)
        }
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
