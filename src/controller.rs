use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use futures::future::{join_all, try_join_all};
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

use crate::{Url, WitnessConfig};

#[derive(Debug)]
pub enum ControllerError {
    MissingIp(BasicPrefix),
}

pub struct Controller {
    resolver_addresses: Vec<Url>,
    saved_witnesses: HashMap<String, Url>,
    controller: Keri<CryptoBox>,
}

impl Controller {
    pub fn new(db_path: &Path, resolver_addresses: Vec<Url>) -> Result<Self> {
        let db = Arc::new(SledEventDatabase::new(db_path)?);

        let key_manager = { Arc::new(Mutex::new(CryptoBox::new()?)) };
        let keri_controller = Keri::new(Arc::clone(&db), key_manager)?;

        Ok(Controller {
            controller: keri_controller,
            resolver_addresses,
            saved_witnesses: HashMap::new(),
        })
    }

    pub async fn init(
        db_path: &Path,
        resolver_addresses: Vec<Url>,
        initial_witnesses: Option<Vec<WitnessConfig>>,
        initial_threshold: Option<SignatureThreshold>,
    ) -> Result<Self> {
        let mut controller = Controller::new(db_path, resolver_addresses)?;
        let initial_witnesses_prefixes = controller
            .save_witness_data(&initial_witnesses.unwrap_or_default())
            .context("Saving initial witness data failed")?;

        let icp_event = controller
            .controller
            .incept(Some(initial_witnesses_prefixes.clone()), initial_threshold)
            .context("Generating incpetion event failed")?;
        let icp_event: SignedEventData = (&icp_event).into();
        println!("\nInception event generated and signed...");

        controller
            .publish_event(&icp_event, &initial_witnesses_prefixes)
            .await
            .context("Publishing inception event failed")?;

        println!(
            "\nTDA initialized succesfully. \nTda identifier: {}\n",
            controller.controller.prefix().to_str()
        );

        Ok(controller)
    }

    async fn get_ips(&self, witnesses: &[BasicPrefix]) -> Result<Vec<Url>> {
        // Try to get ip addresses for witnesses by checking self.saved_witnesses.
        let (found_ips, missing_ips): (_, Vec<Result<_, ControllerError>>) = witnesses
            .iter()
            .map(|w| -> Result<Url, ControllerError> {
                self.saved_witnesses
                    .get(&w.to_str())
                    .map(|i| i.clone())
                    .ok_or(ControllerError::MissingIp(w.clone()))
            })
            .partition(Result::is_ok);

        let adresses_from_resolver = try_join_all(
            missing_ips
                .iter()
                .filter_map(|e| {
                    if let Err(ControllerError::MissingIp(ip)) = e {
                        Some(ip)
                    } else {
                        None
                    }
                })
                .map(|ip|
            // ask resolver about ip
            Self::get_witness_ip(&self.resolver_addresses, ip)),
        )
        .await?;
        // Join found ips and asked ips
        let mut witness_ips: Vec<Url> = found_ips.into_iter().map(Result::unwrap).collect();
        witness_ips.extend(adresses_from_resolver);
        Ok(witness_ips)
    }

    async fn publish_event(
        &self,
        event: &SignedEventData,
        witnesses: &[BasicPrefix],
    ) -> Result<()> {
        let witness_ips = self
            .get_ips(witnesses)
            .await
            .context("Looking up witness IP address failed")?;
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
        .await
        .context("Publishing event to witness failed")?
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
            .collect::<Result<Vec<_>>>()
            .context("Processing witness receipts failed")?;

        try_join_all(witness_ips.iter().map(|ip| {
            client
                .post(&format!("{}publish", ip))
                .body(witness_receipts.join(""))
                .send()
        }))
        .await
        .context("Publishing witness receipts failed")?;
        Ok(())
    }

    pub fn save_witness_data(
        &mut self,
        witness_config: &[WitnessConfig],
    ) -> Result<Vec<BasicPrefix>> {
        // save witnesses location, because they can not be find in resolvers
        witness_config
            .iter()
            .map(|w| {
                if let Ok(loc) = w.get_location() {
                    self.saved_witnesses
                        .insert(w.get_aid().unwrap().to_str(), loc);
                } else {
                    // TODO check if resolver got it id?
                };
                w.get_aid()
            })
            .collect::<Result<Vec<_>>>()
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

        let wits_prefs = self.save_witness_data(&witness_list.unwrap_or_default())?;

        // Get new witnesses address and kerl
        let new_ips = self.get_ips(&witness_to_add.as_ref().unwrap()).await?;

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
            // asume just one key for now
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

    pub async fn get_witness_ip(resolvers: &[Url], witness: &BasicPrefix) -> Result<Url> {
        #[derive(Serialize, Clone, Deserialize)]
        struct Ip {
            pub ip: String,
        }

        let witness_ip = join_all(
            try_join_all(
                resolvers
                    .to_vec()
                    .into_iter()
                    .map(|ip| reqwest::get(format!("{}witness_ips/{}", ip, witness.to_str()))),
            )
            .await?
            .into_iter()
            .map(|r| r.json::<Ip>()),
        )
        .await
        .into_iter()
        .find(|ip| ip.is_ok());

        Ok(Url::parse(&format!(
            "http://{}",
            witness_ip
                .expect("No such witness in registered resolvers")
                .unwrap()
                .ip
        ))?)
    }

    pub async fn get_state_from_resolvers(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<IdentifierState> {
        let state = join_all(
            try_join_all(
                self.resolver_addresses
                    .to_vec()
                    .into_iter()
                    .map(|ip| reqwest::get(format!("{}key_states/{}", ip, prefix.to_str()))),
            )
            .await?
            .into_iter()
            .map(|r| r.json::<IdentifierState>()),
        )
        .await
        .into_iter()
        .find(|state| state.is_ok());

        state
            .ok_or(anyhow::anyhow!(""))?
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    pub async fn get_public_keys(&self, issuer: &IdentifierPrefix) -> Result<Option<KeyConfig>> {
        let log = join_all(
            try_join_all(
                self.resolver_addresses
                    .to_vec()
                    .into_iter()
                    .map(|ip| reqwest::get(format!("{}key_logs/{}", ip, issuer.to_str()))),
            )
            .await?
            .into_iter()
            .map(|r| r.bytes()),
        )
        .await
        .into_iter()
        .filter_map(Result::ok)
        .next();

        let log = match log {
            Some(log) => log,
            None => return Ok(None),
        };

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
