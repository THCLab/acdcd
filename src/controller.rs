use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use keri::{
    database::sled::SledEventDatabase,
    derivation::self_signing::SelfSigning,
    error::Error,
    event::sections::{threshold::SignatureThreshold, KeyConfig},
    event_parsing::SignedEventData,
    keri::Keri,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix},
    signer::{CryptoBox, KeyManager},
    state::IdentifierState,
};
use serde::{Deserialize, Serialize};

pub struct Controller {
    resolver_address: String,
    controller: Keri<CryptoBox>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Ip {
    pub ip: String,
}

impl Controller {
    pub fn new(
        db_path: &Path,
        resolver_address: String,
        initial_witnesses: Option<Vec<BasicPrefix>>,
        initial_threshold: Option<SignatureThreshold>,
    ) -> Self {
        let db = Arc::new(SledEventDatabase::new(db_path).unwrap());

        let key_manager = { Arc::new(Mutex::new(CryptoBox::new().unwrap())) };
        let mut controller = Keri::new(Arc::clone(&db), key_manager.clone()).unwrap();
        let icp_event: SignedEventData = (&controller
            .incept(initial_witnesses.clone(), initial_threshold)
            .unwrap())
            .into();
        println!("\nInception event generated and signed...");

        Self::publish_event(
            &icp_event,
            &initial_witnesses.unwrap_or_default(),
            &resolver_address,
            &controller,
        );

        println!(
            "\nTDA initialized succesfully. \nTda identifier: {}\n",
            controller.prefix().to_str()
        );

        Controller {
            controller,
            resolver_address,
        }
    }

    fn publish_event(
        event: &SignedEventData,
        witnesses: &[BasicPrefix],
        resolver_address: &str,
        controller: &Keri<CryptoBox>,
    ) {
        // Get witnesses ip addresses
        let witness_ips: Vec<_> = witnesses
            .iter()
            .map(|w| {
                let witness_ip: Ip =
                    ureq::get(&format!("{}/witness_ips/{}", resolver_address, w.to_str()))
                        .call()
                        .unwrap()
                        .into_json()
                        .unwrap();
                witness_ip.ip
            })
            .collect();

        println!("\ngot witness adresses: {:?}", witness_ips);

        // send event to witnesses and collect receipts
        let witness_receipts: Vec<_> = witness_ips
            .iter()
            .map(|ip| {
                let kel = ureq::post(&format!("http://{}/publish", ip))
                    .send_bytes(&event.to_cesr().unwrap());
                #[derive(Serialize, Deserialize)]
                struct RespondData {
                    parsed: u64,
                    not_parsed: String,
                    receipts: Vec<String>,
                    errors: Vec<String>,
                }
                let wit_res: Result<RespondData, _> = kel.unwrap().into_json();
                wit_res.unwrap().receipts
            })
            .flatten()
            .collect();

        println!("\ngot {} witness receipts...", witness_receipts.len());

        let flatten_receipts = witness_receipts.join("");
        // process receipts and send them to all of the witnesses
        controller.respond(flatten_receipts.as_bytes()).unwrap();
        // println!(
        //     "\nevent should be accepted now. Current kel in controller: {}\n",
        //     String::from_utf8(controller.get_kerl().unwrap().unwrap()).unwrap()
        // );

        // println!("Sending all receipts to witnesses..");
        witness_ips.iter().for_each(|ip| {
            ureq::post(&format!("http://{}/publish", ip))
                .send_bytes(flatten_receipts.as_bytes())
                .unwrap();
        });
    }

    pub fn rotate(
        &mut self,
        witness_to_add: Option<&[BasicPrefix]>,
        witness_to_remove: Option<&[BasicPrefix]>,
        witness_threshold: Option<SignatureThreshold>,
    ) -> Result<()> {
        let rotation_event =
            self.controller
                .rotate(witness_to_add, witness_to_remove, witness_threshold)?;
        let new_state = self
            .controller
            .get_state()?
            .ok_or(anyhow::anyhow!("There's no state in database"))?;
        let witnesses = new_state.witness_config.witnesses;

        Self::publish_event(
            &SignedEventData::from(&rotation_event),
            &witnesses,
            &self.resolver_address,
            &self.controller,
        );
        println!("\nKeys rotated succesfully.");

        Ok(())
    }

    pub fn sign(&self, data: &[u8]) -> Result<AttachedSignaturePrefix, Error> {
        Ok(AttachedSignaturePrefix::new(
            // assume Ed signature
            SelfSigning::Ed25519Sha512,
            self.controller
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
        key_config.verify(message, signatures)?;

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

        Ok(())
    }

    pub fn get_public_keys(&self, issuer: &IdentifierPrefix) -> Result<KeyConfig> {
        match self.controller.get_state_for_prefix(issuer)? {
            Some(state) => {
                // probably should ask resolver if we have most recent keyconfig
                Ok(state.current)
            }
            None => {
                // no state, we should ask resolver about kel/state
                let state_from_resolver: Result<String, _> = ureq::get(&format!(
                    "{}/key_states/{}",
                    self.resolver_address,
                    issuer.to_str()
                ))
                .call()?
                .into_string();

                println!(
                    "\nAsk resolver about state: {}",
                    state_from_resolver.as_ref().unwrap()
                );
                let state_from_resolver: Result<IdentifierState, _> =
                    serde_json::from_str(&state_from_resolver?);

                Ok(state_from_resolver?.current)
            }
        }
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.controller.prefix().clone()
    }

    pub fn get_kel(&self) -> Result<String> {
        Ok(self.controller.get_kerl().map(|kel| match kel {
            Some(kel) => String::from_utf8(kel).unwrap(),
            None => "".to_string(),
        })?)
    }
}
