use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use futures::future::try_join_all;
use keri::{
    database::sled::SledEventDatabase,
    derivation::self_signing::SelfSigning,
    error::Error,
    event::sections::{threshold::SignatureThreshold, KeyConfig},
    event_parsing::SignedEventData,
    keri::Keri,
    oobi::OobiManager,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix},
    processor::validator::EventValidator,
    signer::{CryptoBox, KeyManager},
    state::IdentifierState,
};
use serde::{Deserialize, Serialize};

use crate::{Url, WitnessConfig};

#[derive(Debug)]
pub enum ControllerError {
    MissingIp(BasicPrefix),
}

pub struct Controller {
    controller: Keri<CryptoBox>,
    oobi_manager: OobiManager,
}

impl Controller {
    pub fn new(db_path: &Path) -> Result<Self> {
        let db = Arc::new(SledEventDatabase::new(db_path)?);

        let key_manager = { Arc::new(Mutex::new(CryptoBox::new()?)) };
        let keri_controller = Keri::new(Arc::clone(&db), key_manager)?;
        let validator = EventValidator::new(db);
        Ok(Controller {
            controller: keri_controller,
            oobi_manager: OobiManager::new(validator),
        })
    }

    pub async fn init(
        db_path: &Path,
        initial_witnesses: Option<Vec<WitnessConfig>>,
        initial_threshold: Option<SignatureThreshold>,
    ) -> Result<Self> {
        let mut controller = Controller::new(db_path)?;
        let initial_witnesses_prefixes = controller
            .save_witness_data(&initial_witnesses.unwrap_or_default())
            .await?;

        let icp_event: SignedEventData = (&controller
            .controller
            .incept(Some(initial_witnesses_prefixes.clone()), initial_threshold)?)
            .into();
        println!("\nInception event generated and signed...");

        controller
            .publish_event(&icp_event, &initial_witnesses_prefixes)
            .await?;

        println!(
            "\nTDA initialized succesfully. \nTda identifier: {}\n",
            controller.controller.prefix().to_str()
        );

        Ok(controller)
    }

    async fn get_ips(&self, witnesses: &[BasicPrefix]) -> Result<Vec<Url>> {
        // Try to get ip addresses for witnesses.
        let (found_ips, missing_ips): (_, Vec<Result<_, _>>) = witnesses
            .iter()
            .map(|w| -> Result<Url, ControllerError> {
                match self
                    .oobi_manager
                    .get_oobi(&IdentifierPrefix::Basic(w.clone()))
                {
                    Some(oobi) => Ok(Url::parse(&format!(
                        "http://{}",
                        &oobi.event.content.data.data.get_url()
                    ))
                    .unwrap()),
                    None => Err(ControllerError::MissingIp(w.clone())),
                }
            })
            .partition(Result::is_ok);

        let adresses_from_resolver = 
        // try_join_all(
            missing_ips
                .iter()
                .filter_map(|e| {
                    if let Err(ControllerError::MissingIp(ip)) = e {
                        Some(ip)
                    } else {
                        None
                    }
                }
            );

        // Join found ips and asked ips
        let mut witness_ips: Vec<Url> = found_ips.into_iter().map(Result::unwrap).collect();
        // witness_ips.extend(adresses_from_resolver);
        Ok(witness_ips)
    }

    async fn publish_event(
        &self,
        event: &SignedEventData,
        witnesses: &[BasicPrefix],
    ) -> Result<()> {
        let witness_ips = self.get_ips(witnesses).await?;
        println!(
            "\ngot witness adresses: {:?}",
            witness_ips
                .iter()
                .map(|w| w.to_string())
                .collect::<Vec<_>>()
        );

        /// Helper struct for deserializing data provided by witnesses
        #[derive(Serialize, Deserialize)]
        struct RespondData {
            parsed: u64,
            not_parsed: String,
            receipts: Vec<String>,
            errors: Vec<String>,
        }

        // send event to witnesses and collect receipts
        let client = reqwest::Client::new();
        let witness_receipts = try_join_all(witness_ips.iter().map(|ip| {
            client
                .post(&format!("{}publish", ip))
                .body(String::from_utf8(event.to_cesr().unwrap()).unwrap())
                .send()
        }))
        .await?
        .into_iter()
        .map(|r| r.json::<RespondData>());

        let witness_receipts = try_join_all(witness_receipts)
            .await
            .unwrap()
            .iter()
            .map(|r| r.receipts.join(""))
            .collect::<Vec<_>>();

        println!("\ngot {} witness receipts...", witness_receipts.len());

        // process receipts and send them to all of the witnesses
        let _processing = witness_receipts
            .iter()
            .map(|rct| -> Result<_> {
                self.controller
                    .respond_single(rct.as_bytes())
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
            })
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();

        try_join_all(witness_ips.iter().map(|ip| {
            client
                .post(&format!("{}publish", ip))
                .body(witness_receipts.join(""))
                .send()
        }))
        .await?;
        Ok(())
    }

    pub async fn save_witness_data(
        &mut self,
        witness_config: &[WitnessConfig],
    ) -> Result<Vec<BasicPrefix>> {
        // resolve witnesses oobi
        // TODO load oobis from config file
        let prefs = witness_config
            .iter()
            .map(|w| {
                let (prefix, location) = match (w.get_aid(), w.get_location()) {
                    (Ok(aid), Ok(location)) => (aid, location),
                    (Ok(aid), Err(_)) => {
                        let loc = Url::parse(
                            &self
                                .oobi_manager
                                .get_oobi(&IdentifierPrefix::Basic(aid.clone()))
                                .unwrap()
                                .event
                                .content
                                .data
                                .data
                                .get_url(),
                        )
                        .unwrap();
                        (aid, loc)
                    }
                    (Err(_), Ok(_)) => todo!(),
                    (Err(_), Err(_)) => todo!(),
                };
                let oobi_url = format!("{}oobi/{}", location, prefix.to_str());
                println!("\n\noobi: {}", oobi_url);
                self.oobi_manager.process_oobi(&oobi_url).unwrap();
                w.get_aid().unwrap()
            })
            .collect::<Vec<_>>();
        self.oobi_manager.load().await?;
        Ok(prefs)
    }

    pub async fn rotate(
        &mut self,
        witness_list: Option<Vec<WitnessConfig>>,
        witness_threshold: Option<u64>,
    ) -> Result<()> {
        let (old_witnesses, old_threshold) = {
            let old_witnesses_config = self
                .get_state()?
                .ok_or(anyhow::anyhow!("There's no state in database"))?
                .witness_config;
            (old_witnesses_config.witnesses, old_witnesses_config.tally)
        };

        // Check threshold
        let new_threshold = match (witness_list.as_ref(), witness_threshold) {
            (None, None) => Ok(old_threshold),
            (None, Some(t)) => {
                if old_witnesses.len() > t as usize {
                    Err(anyhow::anyhow!("Improper thrreshold"))
                } else {
                    Ok(SignatureThreshold::Simple(t))
                }
            }
            (Some(wits), None) => {
                if let SignatureThreshold::Simple(t) = old_threshold {
                    if t > wits.len() as u64 {
                        Err(anyhow::anyhow!("Improper threshold"))
                    } else {
                        Ok(old_threshold)
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

        let (witness_to_add, witness_to_remove) = match witness_list {
            Some(ref new_wits) => {
                let new_witness_prefixes = new_wits
                    .iter()
                    .map(|conf| conf.get_aid().unwrap())
                    .collect::<Vec<_>>();
                (
                    Some(
                        new_witness_prefixes
                            .clone()
                            .into_iter()
                            .filter(|w| !old_witnesses.contains(w))
                            .collect::<Vec<_>>(),
                    ),
                    Some(
                        old_witnesses
                            .clone()
                            .into_iter()
                            .filter(|w| !new_witness_prefixes.contains(w))
                            .collect::<Vec<BasicPrefix>>(),
                    ),
                )
            }
            None => (None, None),
        };

        let wits_prefs = self
            .save_witness_data(&witness_list.unwrap_or_default())
            .await?;

        // Get new witnesses address and kerl
        let new_ips = self.get_ips(witness_to_add.as_ref().unwrap()).await?;

        let kerl: Vec<u8> = [self.get_kel()?.as_bytes(), &self.get_receipts()?].concat();

        // Send kerl and witness receipts to the new witnesses
        let client = reqwest::Client::new();
        let _kel_sending_results = for ip in new_ips {
            client
                .post(&format!("{}publish", ip))
                .body(String::from_utf8(kerl.clone()).unwrap())
                .send()
                .await?;
        };

        let rotation_event = self.controller.rotate(
            witness_to_add.as_deref(),
            witness_to_remove.as_deref(),
            Some(new_threshold),
        )?;

        println!(
            "\nRotation event:\n{}",
            String::from_utf8(rotation_event.serialize()?)?
        );

        self.publish_event(
            &SignedEventData::from(&rotation_event),
            &if wits_prefs.is_empty() {
                old_witnesses
            } else {
                wits_prefs
            },
        )
        .await?;
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
            // assume just one key for now
            0,
        ))
    }

    pub async fn _verify(
        &self,
        issuer: &IdentifierPrefix,
        message: &[u8],
        signatures: &[AttachedSignaturePrefix],
    ) -> Result<()> {
        let key_config = self
            .get_public_keys(issuer)
            .await?
            .ok_or(anyhow::anyhow!("Can't find issuer's keys"))?;
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

    pub async fn get_state_from_resolvers(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<IdentifierState> {
        let oobi_address = self
            .oobi_manager
            .get_oobi(prefix)
            .unwrap()
            .event
            .content
            .data
            .data
            .get_url();
        reqwest::get(format!("{}key_states/{}", oobi_address, prefix.to_str()))
            .await?
            .json::<IdentifierState>()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    pub async fn get_public_keys(&self, issuer: &IdentifierPrefix) -> Result<Option<KeyConfig>> {
        let oobi_address = self
            .oobi_manager
            .get_oobi(issuer)
            .unwrap()
            .event
            .content
            .data
            .data
            .get_url();
        let log = reqwest::get(format!("{}key_logs/{}", oobi_address, issuer.to_str()))
            .await?
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        self.controller
            .parse_and_process(&log)
            .context("Can't parse key event log")?;

        match self.controller.get_state_for_prefix(issuer)? {
            Some(state) => Ok(Some(state.current)),
            None => Ok(None),
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
            .get_receipts_nt(self.controller.prefix())
            .ok_or(anyhow::anyhow!("There are no nontransferable receipts"))?
            .map(|r| {
                let sed: SignedEventData = r.into();
                sed.to_cesr().expect("CESR format problem")
            })
            .flatten()
            .collect::<Vec<_>>())
    }
}
