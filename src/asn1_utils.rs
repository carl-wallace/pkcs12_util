//! Utility functions for interacting with ASN.1 structures associated with PKCS #12 objects

use cms::encrypted_data::EncryptedData;
use der::{
    asn1::{ContextSpecific, OctetString},
    Any, Decode, Encode,
};
use log::error;
use pkcs12::{authenticated_safe::AuthenticatedSafe, cert_type::CertBag, safe_bag::SafeContents};
use rsa::{pkcs8, pkcs8::EncryptedPrivateKeyInfo};

use crate::Error;

pub(crate) fn get_auth_safes(content: &Any) -> crate::Result<AuthenticatedSafe<'_>> {
    let auth_safes_os = OctetString::from_der(&content.to_der()?)?;
    Ok(AuthenticatedSafe::from_der(auth_safes_os.as_bytes())?)
}

pub(crate) fn get_safe_bags(content: &Any) -> crate::Result<SafeContents> {
    let auth_safes_os = OctetString::from_der(&content.to_der()?)?;
    get_safe_bags_from_buffer(auth_safes_os.as_bytes())
}

pub(crate) fn get_safe_bags_from_buffer(content: &[u8]) -> crate::Result<SafeContents> {
    Ok(SafeContents::from_der(content)?)
}

pub(crate) fn get_key(content: &Any, password: &str) -> crate::Result<Vec<u8>> {
    let safe_bags = get_safe_bags(content)?;
    for safe_bag in safe_bags {
        match safe_bag.bag_id {
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID => {
                let cs: ContextSpecific<EncryptedPrivateKeyInfo<'_>> =
                    ContextSpecific::from_der(&safe_bag.bag_value)?;
                let mut ciphertext = cs.value.encrypted_data.to_vec();
                let plaintext = cs
                    .value
                    .encryption_algorithm
                    .decrypt_in_place(password, &mut ciphertext)?;
                return Ok(plaintext.to_vec());
            }
            _ => {
                error!("Unexpected SafeBag type. Ignoring and continuing...");
            }
        };
    }
    Err(Error::Pkcs12Util(String::from(
        "Failed to find SafeBag containing key",
    )))
}

pub(crate) fn get_cert(content: &Any, password: &str) -> crate::Result<Vec<u8>> {
    let enc_data = EncryptedData::from_der(&content.to_der()?)?;

    let enc_params = match enc_data
        .enc_content_info
        .content_enc_alg
        .parameters
        .as_ref()
    {
        Some(r) => r.to_der()?,
        None => {
            return Err(Error::Pkcs12Util(String::from(
                "Failed to obtain reference to parameters",
            )));
        }
    };

    let params = pkcs8::pkcs5::pbes2::Parameters::from_der(&enc_params)?;
    if let Some(ciphertext_os) = enc_data.enc_content_info.encrypted_content {
        let mut ciphertext = ciphertext_os.as_bytes().to_vec();
        let scheme = pkcs5::EncryptionScheme::from(params.clone());
        let plaintext = scheme.decrypt_in_place(password, &mut ciphertext)?;
        let safe_bags = get_safe_bags_from_buffer(plaintext)?;
        for safe_bag in safe_bags {
            match safe_bag.bag_id {
                pkcs12::PKCS_12_CERT_BAG_OID => {
                    let cs: ContextSpecific<CertBag> =
                        ContextSpecific::from_der(&safe_bag.bag_value)?;
                    let cb = cs.value;
                    return Ok(cb.cert_value.as_bytes().to_vec());
                }
                _ => {
                    error!("Unexpected SafeBag type. Ignoring and continuing.");
                }
            };
        }
        Ok(plaintext.to_vec())
    } else {
        Err(Error::Pkcs12Util(String::from(
            "Failed to read encrypted content",
        )))
    }
}
