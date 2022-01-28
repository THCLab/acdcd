use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::Result;
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

pub struct Controller {
    resolver_addresses: Vec<Url>,
    saved_witnesses: HashMap<String, Url>,
    controller: Keri<CryptoBox>,
}

impl Controller {
    pub async fn new(
        db_path: &Path,
        resolver_addresses: Vec<Url>,
        initial_witnesses: Option<Vec<WitnessConfig>>,
        initial_threshold: Option<SignatureThreshold>,
    ) -> Result<Self> {
        let db = Arc::new(SledEventDatabase::new(db_path)?);

        let key_manager = { Arc::new(Mutex::new(CryptoBox::new()?)) };
        let mut keri_controller = Keri::new(Arc::clone(&db), key_manager)?;
        // save witnesses location, because they can not be find in resolvers
        let mut locations = HashMap::new();
        let ini_witnesses = initial_witnesses.map(|witnesses| {
            witnesses
                .iter()
                .map(|w| {
                    if let Ok(loc) = w.get_location() {
                        locations.insert(w.get_aid().unwrap().to_str(), loc);
                    } else {
                        // TODO check if resolver has this id?
                    };
                    w.get_aid()
                })
                .collect::<Result<Vec<_>>>()
                .unwrap()
        });

        let icp_event: SignedEventData =
            (&keri_controller.incept(ini_witnesses.clone(), initial_threshold)?).into();
        println!("\nInception event generated and signed...");

        let controller = Controller {
            controller: keri_controller,
            resolver_addresses,
            saved_witnesses: locations,
        };
        controller
            .publish_event(&icp_event, &ini_witnesses.unwrap_or_default())
            .await?;

        println!(
            "\nTDA initialized succesfully. \nTda identifier: {}\n",
            controller.controller.prefix().to_str()
        );

        Ok(controller)
    }

    async fn get_ips(&self, witnesses: &[BasicPrefix]) -> Result<Vec<Url>> {
        use crate::api::ApiError;
        let (oks_ips, to_ask_ips): (_, Vec<Result<_, ApiError>>) = witnesses
            .iter()
            .map(|w| -> Result<Url, ApiError> {
                // match
                self.saved_witnesses
                    .get(&w.to_str())
                    .map(|i| i.clone())
                    .ok_or(ApiError::MissingIp(w.clone()))
                // {
                //     Some(loc) => Ok(loc.to_owned()),
                //     None => {
                //         // ask resolver about ip
                //         Self::get_witness_ip(&self.resolver_addresses, w)
                //     }
                // }
            })
            .partition(Result::is_ok);

        let ask_res = to_ask_ips
            .iter()
            .filter_map(|e| {
                if let Err(ApiError::MissingIp(ip)) = e {
                    Some(ip)
                } else {
                    None
                }
            })
            .map(|ip|
            // ask resolver about ip
            Self::get_witness_ip(&self.resolver_addresses, ip));
        let asked_ips = try_join_all(ask_res).await?;
        let mut witness_ips: Vec<Url> = oks_ips.into_iter().map(Result::unwrap).collect();
        witness_ips.extend(asked_ips);
        Ok(witness_ips)
    }

    async fn publish_event(
        &self,
        event: &SignedEventData,
        witnesses: &[BasicPrefix],
    ) -> Result<()> {
        // Get witnesses ip addresses

        let witness_ips = self.get_ips(witnesses).await?;
        println!(
            "\ngot witness adresses: {:?}",
            witness_ips
                .iter()
                .map(|w| w.to_string())
                .collect::<Vec<_>>()
        );

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

        let flatten_receipts = witness_receipts.join("");
        // process receipts and send them to all of the witnesses
        let _processing = witness_receipts
            .iter()
            .map(|rct| -> Result<_> {
                self.controller
                    .respond_single(rct.as_bytes())
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        // println!(
        //     "\nevent should be accepted now. Current kel in controller: {}\n",
        //     String::from_utf8(controller.get_kerl().unwrap().unwrap()).unwrap()
        // );

        // println!("Sending all receipts to witnesses..");
        try_join_all(witness_ips.iter().map(|ip| {
            client
                .post(&format!("{}publish", ip))
                .body(flatten_receipts.clone())
                .send()
        }))
        .await?;
        Ok(())
    }

    pub async fn rotate(
        &mut self,
        witness_list: Option<Vec<WitnessConfig>>,
        witness_threshold: Option<u64>,
    ) -> Result<()> {
        let old_witnesses_config = self
            .get_state()?
            .ok_or(anyhow::anyhow!("There's no state in database"))?
            .witness_config;
        let old_witnesses = old_witnesses_config.witnesses;

        let new_threshold = match (witness_list.as_ref(), witness_threshold) {
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

        // save witnesses location, because they can not be find in resolvers
        let wits_prefs = witness_list
            .unwrap_or_default()
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
            .collect::<Result<Vec<_>>>();

        // let wits_prefs = witness_list.map(|w| w.iter().map(|w| w.get_aid().unwrap()).collect());

        let rotation_event = self.controller.rotate(
            witness_to_add.as_deref(),
            witness_to_remove.as_deref(),
            Some(new_threshold),
        )?;
        // send kerl and witness receipts to the new witnesses
        // Get new witnesses address

        let new_ips = self.get_ips(&witness_to_add.unwrap()).await?;

        let kerl: Vec<u8> = [self.get_kel()?.as_bytes(), &self.get_receipts()?].concat();

        // send them kel and receipts
        let client = reqwest::Client::new();
        let _kel_sending_results = for ip in new_ips {
            client
                .post(&format!("{}publish", ip))
                .body(String::from_utf8(kerl.clone()).unwrap())
                .send()
                .await?;
        };

        println!(
            "\nRotation event:\n{}",
            String::from_utf8(rotation_event.serialize()?)?
        );

        self.publish_event(
            &SignedEventData::from(&rotation_event),
            &wits_prefs.unwrap_or(old_witnesses),
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
        let key_config = self.get_public_keys(issuer).await?;
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
        // let ip_responses: Vec<_> = try_join_all(resolvers.iter().find_map(|res| {
        //     reqwest::get(
        //         res.join(&format!("witness_ips/{}", witness.to_str()))
        //             .unwrap()
        //             .as_str(),
        //     )})).await?;
        //     ip_responses.iter().map(|res| res.json());
        //     // .json()
        //     // .map_err(|e| anyhow::anyhow!(e.to_string()))
        //     // .unwrap()

        Ok(Url::parse(&format!(
            "http://{}",
            witness_ip
                .expect("No such witness in registered resolvers")
                .expect("No such witness in registered resolvers")
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

    pub async fn get_public_keys(&self, issuer: &IdentifierPrefix) -> Result<KeyConfig> {
        match self.controller.get_state_for_prefix(issuer)? {
            Some(state) => {
                // probably should ask resolver if we have most recent keyconfig
                Ok(state.current)
            }
            None => {
                // no state, we should ask resolver about kel/state
                let state_from_resolver = self.get_state_from_resolvers(issuer);
                Ok(state_from_resolver.await?.current)
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
