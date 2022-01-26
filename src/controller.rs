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

use crate::Url;

pub struct Controller {
    resolver_addresses: Vec<Url>,
    controller: Keri<CryptoBox>,
}

impl Controller {
    pub fn new(
        db_path: &Path,
        resolver_addresses: Vec<Url>,
        initial_witnesses: Option<Vec<BasicPrefix>>,
        initial_threshold: Option<SignatureThreshold>,
    ) -> Result<Self> {
        let db = Arc::new(SledEventDatabase::new(db_path)?);

        let key_manager = { Arc::new(Mutex::new(CryptoBox::new()?)) };
        let mut controller = Keri::new(Arc::clone(&db), key_manager.clone())?;
        let icp_event: SignedEventData =
            (&controller.incept(initial_witnesses.clone(), initial_threshold)?).into();
        println!("\nInception event generated and signed...");

        Self::publish_event(
            &icp_event,
            &initial_witnesses.unwrap_or_default(),
            &resolver_addresses,
            &controller,
        )?;

        println!(
            "\nTDA initialized succesfully. \nTda identifier: {}\n",
            controller.prefix().to_str()
        );

        Ok(Controller {
            controller,
            resolver_addresses,
        })
    }

    fn publish_event(
        event: &SignedEventData,
        witnesses: &[BasicPrefix],
        resolver_address: &[Url],
        controller: &Keri<CryptoBox>,
    ) -> Result<()> {
        // Get witnesses ip addresses
        let witness_ips = witnesses
            .iter()
            .map(|w| -> Result<String> { Self::get_witness_ip(resolver_address, w) })
            .collect::<Result<Vec<_>>>()?;

        println!("\ngot witness adresses: {:?}", witness_ips);

        // send event to witnesses and collect receipts
        let witness_receipts = witness_ips
            .iter()
            .map(|ip| -> Result<String> {
                let kel =
                    ureq::post(&format!("http://{}/publish", ip)).send_bytes(&event.to_cesr()?);
                #[derive(Serialize, Deserialize)]
                struct RespondData {
                    parsed: u64,
                    not_parsed: String,
                    receipts: Vec<String>,
                    errors: Vec<String>,
                }
                let wit_res: Result<RespondData, _> = kel?.into_json();
                wit_res
                    .map(|r| r.receipts.join(""))
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
            })
            // .flatten()
            .collect::<Result<Vec<_>>>()?;

        println!("\ngot {} witness receipts...", witness_receipts.len());

        let flatten_receipts = witness_receipts.join("");
        // process receipts and send them to all of the witnesses
        let _processing = witness_receipts
            .iter()
            .map(|rct| {
                controller.respond_single(rct.as_bytes()).unwrap()
            }).collect::<Vec<_>>();
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
        Ok(())
    }

    pub fn rotate(
        &mut self,
        witness_list: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<u64>,
    ) -> Result<()> {
        let old_witnesses_config = self
            .get_state()?
            .ok_or(anyhow::anyhow!("There's no state in database"))?
            .witness_config;
        let old_witnesses = old_witnesses_config.witnesses;

        let new_threshold = match (witness_list.clone(), witness_threshold) {
            (None, None) => Ok(old_witnesses_config.tally),
            (None, Some(t)) => {
                if old_witnesses.len() > t as usize {
                    Err(anyhow::anyhow!("Improper thrreshold"))
                } else {
                    Ok(SignatureThreshold::Simple(t))
                }
            }
            (Some(wits), None) => {
                if let SignatureThreshold::Simple(t) = old_witnesses_config.tally {
                    if t > wits.len() as u64 {
                        Err(anyhow::anyhow!("Improper threshold"))
                    } else {
                        Ok(old_witnesses_config.tally)
                    }
                } else {
                    Err(anyhow::anyhow!("Improper threshold"))
                }
            }
            (Some(wits), Some(t)) => {
                if t > wits.len() as u64 {
                    Err(anyhow::anyhow!("Improper threshold"))
                } else {
                    Ok(SignatureThreshold::Simple(t))
                }
            }
        }?;

        let (witness_to_add, witness_to_remove) = match witness_list.clone() {
            Some(new_wits) => (
                Some(
                    new_wits
                        .clone()
                        .into_iter()
                        .filter(|w| !old_witnesses.contains(w))
                        .collect::<Vec<_>>(),
                ),
                Some(
                    old_witnesses
                        .clone()
                        .into_iter()
                        .filter(|w| !new_wits.contains(w))
                        .collect::<Vec<BasicPrefix>>(),
                ),
            ),
            None => (None, None),
        };

        let rotation_event = self.controller.rotate(
            witness_to_add.as_deref(),
            witness_to_remove.as_deref(),
            Some(new_threshold),
        )?;
        // send kerl and witness receipts to the new witnesses
        // Get new witnesses address
        let new_ips = witness_to_add
            .unwrap_or_default()
            .into_iter()
            .map(|w| -> Result<String> {
                let witness_ip = Self::get_witness_ip(&self.resolver_addresses, &w);
                witness_ip
            })
            .collect::<Result<Vec<_>>>()?;

        let kerl: Vec<u8> = [self.get_kel()?.as_bytes(), &self.get_receipts()?].concat();
        // send them kel and receipts
        let _kel_sending_results = new_ips
            .iter()
            .map(|ip| ureq::post(&format!("http://{}/publish", ip)).send_bytes(&kerl))
            .collect::<Vec<_>>();

        println!(
            "\nRotation event:\n{}",
            String::from_utf8(rotation_event.serialize()?)?
        );

        Self::publish_event(
            &SignedEventData::from(&rotation_event),
            &witness_list.unwrap_or(old_witnesses),
            &self.resolver_addresses,
            &self.controller,
        )?;
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

    pub fn _verify(
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

    pub fn get_witness_ip(resolvers: &[Url], witness: &BasicPrefix) -> Result<String> {
        #[derive(Serialize, Deserialize, Clone)]
        struct Ip {
            pub ip: String,
        }
        let witness_ip: Option<Ip> = resolvers.iter().find_map(|res| {
            ureq::get(
                res.join(&format!("witness_ips/{}", witness.to_str()))
                    .unwrap()
                    .as_str(),
            )
            .call()
            .unwrap()
            .into_json()
            .unwrap()
        });
        Ok(witness_ip
            .expect("No such witness in registered resolvers")
            .ip)
    }

    pub fn get_state_from_resolvers(&self, prefix: &IdentifierPrefix) -> Result<IdentifierState> {
        let state_from_resolvers: String = self
            .resolver_addresses
            .iter()
            .find_map(|res| {
                ureq::get(&format!("{}/key_states/{}", res, prefix.to_str()))
                    .call()
                    .unwrap()
                    .into_json()
                    .unwrap()
            })
            .ok_or(anyhow::anyhow!("State can't be found in resolvers"))?;
        println!("\nAsk resolver about state: {}", state_from_resolvers);
        let state_from_resolver: Result<IdentifierState, _> =
            serde_json::from_str(&state_from_resolvers);

        Ok(state_from_resolver?)
    }

    pub fn get_public_keys(&self, issuer: &IdentifierPrefix) -> Result<KeyConfig> {
        match self.controller.get_state_for_prefix(issuer)? {
            Some(state) => {
                // probably should ask resolver if we have most recent keyconfig
                Ok(state.current)
            }
            None => {
                // no state, we should ask resolver about kel/state
                let state_from_resolver = self.get_state_from_resolvers(issuer);
                Ok(state_from_resolver?.current)
            }
        }
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.controller.prefix().clone()
    }

    pub fn get_kel(&self) -> Result<String> {
        Ok(self
            .controller
            .get_kerl()?
            .map(|kel| String::from_utf8(kel).expect("kel can't be converted to string"))
            .unwrap_or_default())
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>> {
        Ok(self.controller.get_state()?)
    }

    pub fn get_receipts(&self) -> Result<Vec<u8>> {
        Ok(self
            .controller
            .db()
            .get_receipts_nt(&self.controller.prefix())
            .ok_or(anyhow::anyhow!("There are no nontransferable receipts"))?
            .map(|r| {
                let sed: SignedEventData = r.into();
                sed.to_cesr().expect("CESR format problem")
            })
            .flatten()
            .collect::<Vec<_>>())
    }
}
