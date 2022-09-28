use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::env::{log_str, signer_account_pk};
use near_sdk::near_bindgen;

mod errors;

pub struct ED25519SecretKey(pub [u8; ed25519_dalek::KEYPAIR_LENGTH]);

#[near_bindgen]
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct Contract {}

#[near_bindgen]
impl Contract {
    pub fn generate_signature(&self, msg: String, private_key: String) -> Vec<u8> {
        let secret_key = Self::secret_key_from_str(&private_key).unwrap();
        let keypair = Keypair::from_bytes(&secret_key.0).unwrap();
        let signature = keypair.sign(msg.as_bytes()).to_bytes().to_vec();
        log_str(&format!("{:?}", signature));
        signature
    }

    pub fn verify_signature(&mut self, msg: String, signature: Vec<u8>) -> bool {
        let public_key = PublicKey::from_bytes(&signer_account_pk().into_bytes()[1..]).unwrap();
        let signature = Signature::try_from(&signature[..]).unwrap();
        public_key.verify(msg.as_bytes(), &signature).is_ok()
    }
}

impl Contract {
    fn get_key_data(value: &str) -> Result<&str, crate::errors::ParseKeyTypeError> {
        if let Some(idx) = value.find(':') {
            let (_prefix, key_data) = value.split_at(idx);
            Ok(&key_data[1..])
        } else {
            Err(crate::errors::ParseKeyTypeError::UnknownKeyType {
                unknown_key_type: value.to_ascii_lowercase(),
            })
        }
    }

    fn secret_key_from_str(s: &str) -> Result<ED25519SecretKey, crate::errors::ParseKeyError> {
        let key_data = Self::get_key_data(s)?;
        let mut array = [0; ed25519_dalek::KEYPAIR_LENGTH];
        let length = bs58::decode(key_data).into(&mut array[..]).map_err(|err| {
            crate::errors::ParseKeyError::InvalidData {
                error_message: err.to_string(),
            }
        })?;
        if length != ed25519_dalek::KEYPAIR_LENGTH {
            return Err(crate::errors::ParseKeyError::InvalidLength {
                expected_length: ed25519_dalek::KEYPAIR_LENGTH,
                received_length: length,
            });
        }
        Ok(ED25519SecretKey(array))
    }
}
