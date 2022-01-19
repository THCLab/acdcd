use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use keri::{
    database::sled::SledEventDatabase,
    derivation::self_signing::SelfSigning,
    error::Error,
    event::sections::KeyConfig,
    keri::Keri,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix},
    signer::{CryptoBox, KeyManager},
    state::IdentifierState,
};

pub struct Controller(Keri<CryptoBox>);

impl Controller {
    pub fn new(db_path: &Path, initial_witnesses: Option<Vec<BasicPrefix>>) -> Self {
        let db = Arc::new(SledEventDatabase::new(db_path).unwrap());

        let key_manager = { Arc::new(Mutex::new(CryptoBox::new().unwrap())) };
        let mut controller = Keri::new(Arc::clone(&db), key_manager.clone()).unwrap();
        controller.incept(initial_witnesses);

        Controller(controller)
    }

    pub fn sign(&self, data: &[u8]) -> Result<AttachedSignaturePrefix, Error> {
        Ok(AttachedSignaturePrefix::new(
            // assum Ed signature
            SelfSigning::Ed25519Sha512,
            self.0
                .key_manager()
                .lock()
                .map_err(|_| Error::MutexPoisoned)?
                .sign(data)?,
            // asume just one key for now
            0,
        ))
    }

    pub fn verify(
        &self,
        issuer: &IdentifierPrefix,
        message: &[u8],
        signatures: &[AttachedSignaturePrefix],
    ) -> Result<()> {
        let key_config = self.get_public_keys(issuer)?;

        // Logic for determining the index of the signature
        // into attached signature prefix to check signature threshold
        // let indexed_signatures: Result<Vec<AttachedSignaturePrefix>> = signatures
        //     .iter()
        //     .map(|signature| {
        //         (
        //             key_config
        //                 .public_keys
        //                 .iter()
        //                 .position(|x| x.verify(message, signature).unwrap()),
        //             // .ok_or(napi::Error::from_reason(format!("There is no key for signature: {}", signature.to_str())).unwrap(),
        //             signature,
        //         )
        //     })
        //     .map(|(i, signature)| match i {
        //         Some(i) => Ok(AttachedSignaturePrefix { index: i as u16, signature: signature.clone() }),
        //         None => {
        // 			// signature don't match any public key
        // 			todo!()
        // 		},
        //     })
        //     .collect();

        key_config.verify(message, signatures)?;

        Ok(())
    }

    pub fn get_public_keys(&self, issuer: &IdentifierPrefix) -> Result<KeyConfig> {
        match self.0.get_state_for_prefix(issuer)? {
            Some(state) => Ok(state.current),
            None => {
                // no state, we should ask resolver about kel/state
                todo!()
            }
        }
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.0.prefix().clone()
    }

    pub fn get_state(&self) -> Result<IdentifierState> {
        Ok(self.0.get_state()?.unwrap())
    }

    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.0.key_manager().lock().unwrap().public_key().key())
    }
}
