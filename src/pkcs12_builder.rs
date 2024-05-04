//! Structure to help with generating PKCS #12 objects

use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use rsa::pkcs8::{spki::AlgorithmIdentifier, EncryptedPrivateKeyInfo};
use sha2::{Sha256, Sha384, Sha512};

use cms::{
    content_info::{CmsVersion, ContentInfo},
    encrypted_data::EncryptedData,
    enveloped_data::EncryptedContentInfo,
};
use const_oid::{
    db::{
        rfc5911::{ID_DATA, ID_ENCRYPTED_DATA},
        rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512},
    },
    ObjectIdentifier,
};
use der::{
    asn1::{OctetString, SetOfVec},
    Any, AnyRef, Decode, Encode,
};
use hmac::digest::crypto_common;
use pkcs12::{
    cert_type::CertBag,
    digest_info::DigestInfo,
    kdf::{derive_key_utf8, Pkcs12KeyType},
    mac_data::MacData,
    pfx::{Pfx, Version},
    safe_bag::SafeBag,
    PKCS_12_CERT_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID, PKCS_12_X509_CERT_OID,
};
use pkcs5::{
    pbes2,
    pbes2::{Kdf, Pbkdf2Params, Pbkdf2Prf, AES_256_CBC_OID, PBES2_OID},
};
use x509_cert::{attr::Attribute, spki::AlgorithmIdentifierOwned, Certificate};

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),
    /// InvalidLength
    InvalidLength(crypto_common::InvalidLength),
    /// General errors.
    Builder(String),
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}
impl From<crypto_common::InvalidLength> for Error {
    fn from(err: crypto_common::InvalidLength) -> Error {
        Error::InvalidLength(err)
    }
}
type Result<T> = core::result::Result<T, Error>;

/// Supported MAC algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacAlgorithm {
    /// HMAC SHA256
    HmacSha256,
    /// HMAC SHA384
    HmacSha384,
    /// HMAC SHA512
    HmacSha512,
}

impl MacAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            MacAlgorithm::HmacSha256 => ID_SHA_256,
            MacAlgorithm::HmacSha384 => ID_SHA_384,
            MacAlgorithm::HmacSha512 => ID_SHA_512,
        }
    }

    /// Return the block size of the associated digest algorithm.
    pub fn block_size(&self) -> i16 {
        match self {
            MacAlgorithm::HmacSha256 => 32,
            MacAlgorithm::HmacSha384 => 48,
            MacAlgorithm::HmacSha512 => 64,
        }
    }

    /// Return encoded parameters for inclusion in an AlgorithmIdentifier
    pub fn parameters(&self) -> Vec<u8> {
        vec![0x05, 0x00]
    }
}

/// Supported KDF algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncryptionAlgorithm {
    /// AES128 CBC
    Aes128Cbc,
    /// AES-192 CBC
    Aes192Cbc,
    /// AES-256 CBC
    Aes256Cbc,
}

impl EncryptionAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            EncryptionAlgorithm::Aes128Cbc => const_oid::db::rfc5911::ID_AES_128_CBC,
            EncryptionAlgorithm::Aes192Cbc => const_oid::db::rfc5911::ID_AES_192_CBC,
            EncryptionAlgorithm::Aes256Cbc => const_oid::db::rfc5911::ID_AES_256_CBC,
        }
    }
}

/// Helper for building password-based MacData objects for inclusion in a PKCS #12 object
pub struct MacDataBuilder {
    digest_algorithm: MacAlgorithm,
    salt: Option<Vec<u8>>,
    iterations: Option<i32>,
}
impl MacDataBuilder {
    /// Creates a new MacDataBuilder instance with no salt, suitable for use with build_with_rng as-is
    /// or for further customization prior to invoking build. By default, iterations will be set to 2048.
    pub fn new(digest_algorithm: MacAlgorithm) -> MacDataBuilder {
        MacDataBuilder {
            digest_algorithm,
            salt: None,
            iterations: None,
        }
    }

    /// Specify a salt value for use on subsequent build or build_with_rng invocation.
    pub fn salt(&mut self, salt: Option<Vec<u8>>) {
        self.salt = salt;
    }

    /// Specify an iterations value for use on subsequent build or build_with_rng invocations.
    pub fn iterations(&mut self, iterations: Option<i32>) {
        self.iterations = iterations;
    }

    /// Generate MAC key given a password and a salt
    fn generate_mac_key(&self, password: &str, salt: &[u8]) -> Result<Vec<u8>> {
        let iterations = self.iterations.unwrap_or(2048);

        match self.digest_algorithm {
            MacAlgorithm::HmacSha256 => Ok(derive_key_utf8::<Sha256>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.block_size() as usize,
            )?),
            MacAlgorithm::HmacSha384 => Ok(derive_key_utf8::<Sha384>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.block_size() as usize,
            )?),
            MacAlgorithm::HmacSha512 => Ok(derive_key_utf8::<Sha512>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.block_size() as usize,
            )?),
        }
    }

    /// Generate a MAC given a MAC key and content
    fn generate_mac(&self, mac_key: &[u8], content: &[u8]) -> Result<Vec<u8>> {
        match self.digest_algorithm {
            MacAlgorithm::HmacSha256 => {
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(mac_key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacAlgorithm::HmacSha384 => {
                type HmacSha384 = Hmac<Sha384>;
                let mut mac = HmacSha384::new_from_slice(mac_key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacAlgorithm::HmacSha512 => {
                type HmacSha512 = Hmac<Sha512>;
                let mut mac = HmacSha512::new_from_slice(mac_key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }

    /// Builds a MacData instance using a previously specified salt value and a previously specified
    /// (or default) iterations value. If no iterations value has been specified, a default of 2048
    /// is used.
    pub fn build(&self, password: &str, content: &[u8]) -> Result<MacData> {
        let salt = match &self.salt {
            Some(salt) => salt,
            None => return Err(Error::Builder(String::from("No salt provided for MacData"))),
        };

        let mac_key = self.generate_mac_key(password, salt)?;
        let result = self.generate_mac(&mac_key, content)?;
        let mac_os = OctetString::new(result.as_slice())?;
        let mac_salt = OctetString::new(salt.as_slice())?;
        let params_bytes = self.digest_algorithm.parameters();
        let params_ref = Some(Any::from(AnyRef::from_der(&params_bytes)?));

        Ok(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifier {
                    oid: self.digest_algorithm.oid(),
                    parameters: params_ref,
                },
                digest: mac_os,
            },
            mac_salt,
            iterations: self.iterations.unwrap_or(2048),
        })
    }
}

/// Helper for building PKCS #12 objects that feature one key and one certificate (for which no
/// pairwise consistency check is performed). For each of key and certificate, a KDF algorithm, a
/// certificate algorithm and a set of attributes may be specified. By default, PBKDF2 with SHA 256 HMAC
/// is used as the KDF algorithm and AES 256 CBC is used as the encryption algorithm.
pub struct Pkcs12Builder {
    cert_attributes: Option<SetOfVec<Attribute>>,
    cert_kdf_algorithm: Option<Pbkdf2Prf>,
    cert_enc_algorithm: Option<EncryptionAlgorithm>,
    cert_kdf_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    cert_enc_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    key_attributes: Option<SetOfVec<Attribute>>,
    key_kdf_algorithm: Option<Pbkdf2Prf>,
    key_enc_algorithm: Option<EncryptionAlgorithm>,
    key_kdf_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    key_enc_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    mac_data_builder: Option<MacDataBuilder>,
}

impl Default for Pkcs12Builder {
    /// Generate a new Pkcs12Builder instance with all default values.
    fn default() -> Self {
        Pkcs12Builder::new()
    }
}

impl Pkcs12Builder {
    /// Generate a new Pkcs12Builder instance with all default values.
    pub fn new() -> Pkcs12Builder {
        Pkcs12Builder {
            cert_attributes: None,
            cert_kdf_algorithm: None,
            cert_enc_algorithm: None,
            cert_kdf_algorithm_identifier: None,
            cert_enc_algorithm_identifier: None,
            key_attributes: None,
            key_kdf_algorithm: None,
            key_enc_algorithm: None,
            key_kdf_algorithm_identifier: None,
            key_enc_algorithm_identifier: None,
            mac_data_builder: None,
        }
    }

    /// Set attributes to associated with the certificate included in the generated PKCS #12 object.
    pub fn cert_attributes(&mut self, attrs: Option<SetOfVec<Attribute>>) -> &mut Self {
        self.cert_attributes = attrs;
        self
    }
    /// Set the KDF algorithm to use when protecting the certificate included in the generated PKCS #12 object.
    pub fn cert_kdf_algorithm(&mut self, alg: Option<Pbkdf2Prf>) -> &mut Self {
        self.cert_kdf_algorithm_identifier = None;
        self.cert_kdf_algorithm = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the certificate included in the generated PKCS #12 object.
    pub fn cert_enc_algorithm(&mut self, alg: Option<EncryptionAlgorithm>) -> &mut Self {
        self.cert_enc_algorithm_identifier = None;
        self.cert_enc_algorithm = alg;
        self
    }
    /// Set the KDF algorithm to use when protecting the certificate included in the generated PKCS
    /// #12 object using a fully populated AlgorithmIdentifier instance.
    pub fn cert_kdf_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.cert_kdf_algorithm = None;
        self.cert_kdf_algorithm_identifier = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the certificate included in the generated PKCS
    /// #12 object using a fully populated AlgorithmIdentifier instance.
    pub fn cert_enc_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.cert_enc_algorithm = None;
        self.cert_enc_algorithm_identifier = alg;
        self
    }
    /// Set attributes to associated with the key included in the generated PKCS #12 object.
    pub fn key_attributes(&mut self, attrs: Option<SetOfVec<Attribute>>) -> &mut Self {
        self.key_attributes = attrs;
        self
    }
    /// Set the KDF algorithm to use when protecting the key included in the generated PKCS #12 object.
    pub fn key_kdf_algorithm(&mut self, alg: Option<Pbkdf2Prf>) -> &mut Self {
        self.key_kdf_algorithm_identifier = None;
        self.key_kdf_algorithm = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the key included in the generated PKCS #12 object.
    pub fn key_enc_algorithm(&mut self, alg: Option<EncryptionAlgorithm>) -> &mut Self {
        self.key_enc_algorithm_identifier = None;
        self.key_enc_algorithm = alg;
        self
    }
    /// Set the KDF algorithm to use when protecting the key included in the generated PKCS
    /// #12 object using a fully populated AlgorithmIdentifier instance.
    pub fn key_kdf_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.key_kdf_algorithm = None;
        self.key_kdf_algorithm_identifier = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the key included in the generated PKCS
    /// #12 object using a fully populated AlgorithmIdentifier instance.
    pub fn key_enc_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.key_enc_algorithm = None;
        self.key_enc_algorithm_identifier = alg;
        self
    }
    /// Set a MacDataBuilder instance for use in generating a MAC for the PKCS #12 object.
    pub fn mac_data_builder(&mut self, mdb: Option<MacDataBuilder>) -> &mut Self {
        self.mac_data_builder = mdb;
        self
    }

    fn default_mac_data<R>(rng: &mut R) -> Result<MacDataBuilder>
    where
        R: CryptoRngCore,
    {
        let mut salt = vec![0_u8; 8];
        rng.fill_bytes(salt.as_mut_slice());

        let mut md_builder = MacDataBuilder::new(MacAlgorithm::HmacSha256);
        md_builder.iterations(Some(2048));
        md_builder.salt(Some(salt.to_vec()));
        Ok(md_builder)
    }
    fn default_kdf_alg<R>(rng: &mut R) -> Result<AlgorithmIdentifierOwned>
    where
        R: CryptoRngCore,
    {
        let mut salt = vec![0_u8; 8];
        rng.fill_bytes(salt.as_mut_slice());

        let cert_kdf_params = Pbkdf2Params {
            salt: &salt,
            iteration_count: 2048,
            key_length: None,
            prf: Pbkdf2Prf::HmacWithSha256,
        };
        let enc_cert_kdf_params = cert_kdf_params.to_der()?;
        let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice())?;
        Ok(AlgorithmIdentifierOwned {
            oid: PBES2_OID,
            parameters: Some(Any::from(enc_cert_kdf_params_ref)),
        })
    }

    fn default_enc_alg<R>(rng: &mut R) -> Result<AlgorithmIdentifierOwned>
    where
        R: CryptoRngCore,
    {
        let mut iv = vec![0_u8; 16];
        rng.fill_bytes(iv.as_mut_slice());

        let cert_iv = OctetString::new(iv)?.to_der()?;
        let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice())?;
        Ok(AlgorithmIdentifier {
            oid: AES_256_CBC_OID,
            parameters: Some(Any::from(cert_iv_ref)),
        })
    }

    /// Builds a PKCS #12 object containing the provided certificate and key protected using password-based
    /// encryption and MAC. Where KDF, encryption or MAC details have not been previously specified
    /// default values are used with the provided RNG used to generate any necessary random values.
    pub fn build_with_rng<R>(
        &mut self,
        certificate: Certificate,
        key: &[u8],
        password: &str,
        rng: &mut R,
    ) -> Result<Vec<u8>>
    where
        R: CryptoRngCore,
    {
        if let Some(prf) = self.cert_kdf_algorithm {
            let mut salt = vec![0_u8; 8];
            rng.fill_bytes(salt.as_mut_slice());

            let cert_kdf_params = Pbkdf2Params {
                salt: &salt,
                iteration_count: 2048,
                key_length: None,
                prf,
            };
            let enc_cert_kdf_params = cert_kdf_params.to_der()?;
            let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice())?;
            self.cert_kdf_algorithm_identifier(Some(AlgorithmIdentifierOwned {
                oid: PBES2_OID,
                parameters: Some(Any::from(enc_cert_kdf_params_ref)),
            }));
        }

        if let Some(enc_alg) = &self.cert_enc_algorithm {
            let mut iv = vec![0_u8; 16];
            rng.fill_bytes(iv.as_mut_slice());

            let cert_iv = OctetString::new(iv)?.to_der()?;
            let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice())?;
            self.cert_enc_algorithm_identifier(Some(AlgorithmIdentifier {
                oid: enc_alg.oid(),
                parameters: Some(Any::from(cert_iv_ref)),
            }));
        }

        if let Some(prf) = self.key_kdf_algorithm {
            let mut salt = vec![0_u8; 8];
            rng.fill_bytes(salt.as_mut_slice());

            let cert_kdf_params = Pbkdf2Params {
                salt: &salt,
                iteration_count: 2048,
                key_length: None,
                prf,
            };
            let enc_cert_kdf_params = cert_kdf_params.to_der()?;
            let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice())?;
            self.key_kdf_algorithm_identifier(Some(AlgorithmIdentifierOwned {
                oid: PBES2_OID,
                parameters: Some(Any::from(enc_cert_kdf_params_ref)),
            }));
        }

        if let Some(enc_alg) = &self.key_enc_algorithm {
            let mut iv = vec![0_u8; 16];
            rng.fill_bytes(iv.as_mut_slice());

            let cert_iv = OctetString::new(iv)?.to_der()?;
            let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice())?;
            self.key_enc_algorithm_identifier(Some(AlgorithmIdentifier {
                oid: enc_alg.oid(),
                parameters: Some(Any::from(cert_iv_ref)),
            }));
        }

        if self.cert_kdf_algorithm_identifier.is_none() {
            self.cert_kdf_algorithm_identifier = Some(Self::default_kdf_alg(rng)?);
        }
        if self.cert_enc_algorithm_identifier.is_none() {
            self.cert_enc_algorithm_identifier = Some(Self::default_enc_alg(rng)?);
        }
        if self.key_kdf_algorithm_identifier.is_none() {
            self.key_kdf_algorithm_identifier = Some(Self::default_kdf_alg(rng)?);
        }
        if self.key_enc_algorithm_identifier.is_none() {
            self.key_enc_algorithm_identifier = Some(Self::default_enc_alg(rng)?);
        }
        if self.mac_data_builder.is_none() {
            self.mac_data_builder = Some(Self::default_mac_data(rng)?);
        }
        if let Some(mdb) = &mut self.mac_data_builder {
            if mdb.salt.is_none() {
                let mut salt = vec![0_u8; 8];
                rng.fill_bytes(salt.as_mut_slice());
                mdb.salt(Some(salt));
            }
        }
        self.build(certificate, key, password)
    }

    /// Builds a PKCS #12 object containing the provided certificate and key protected using password-based
    /// encryption and MAC. KDF, encryption and MAC information must have been previously provided to
    /// successfully use this function. To use default values, use the build_with_rng function.
    pub fn build(&self, certificate: Certificate, key: &[u8], password: &str) -> Result<Vec<u8>> {
        let der_cert = certificate.to_der()?;
        let cert_bag = CertBag {
            cert_id: PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(der_cert.clone())?,
        };
        let der_cert_bag_inner = cert_bag.to_der()?;
        let cert_safe_bag = SafeBag {
            bag_id: PKCS_12_CERT_BAG_OID,
            bag_value: der_cert_bag_inner,
            bag_attributes: self.cert_attributes.clone(),
        };
        let der_cert_safe_bags = vec![cert_safe_bag].to_der()?;

        let der_cert_kdf_alg = match &self.cert_kdf_algorithm_identifier {
            Some(cert_kdf_alg) => match &cert_kdf_alg.parameters {
                Some(params) => params.to_der()?,
                None => {
                    return Err(Error::Builder(String::from(
                        "No parameters provided for certificate KDF algorithm",
                    )))
                }
            },
            None => {
                return Err(Error::Builder(String::from(
                    "No certificate KDF algorithm provided",
                )))
            }
        };

        let cert_kdf = Kdf::from(Pbkdf2Params::from_der(&der_cert_kdf_alg)?);

        let der_cert_enc_alg = match &self.cert_enc_algorithm_identifier {
            Some(cert_enc_alg) => cert_enc_alg.to_der()?,
            None => {
                return Err(Error::Builder(String::from(
                    "No certificate encryption algorithm provided",
                )))
            }
        };
        let cert_encryption = pbes2::EncryptionScheme::from_der(&der_cert_enc_alg)?;

        let cert_params = pbes2::Parameters {
            kdf: cert_kdf,
            encryption: cert_encryption,
        };
        let cert_scheme = pkcs5::EncryptionScheme::from(cert_params.clone());
        let mut enc_buf = vec![];
        enc_buf.extend_from_slice(&der_cert_safe_bags);
        enc_buf.extend_from_slice(vec![0x00; 16].as_slice());
        let cert_ciphertext =
            match cert_scheme.encrypt_in_place(password, &mut enc_buf, der_cert_safe_bags.len()) {
                Ok(ct) => ct,
                Err(e) => {
                    return Err(Error::Builder(
                        format!("Failed to encrypt certificate: {e:?}").to_string(),
                    ))
                }
            };

        let der_cert_params = cert_params.to_der()?;
        let der_cert_params_ref = AnyRef::try_from(der_cert_params.as_slice())?;

        let enc_data1 = EncryptedData {
            version: CmsVersion::V0,
            enc_content_info: EncryptedContentInfo {
                content_type: ID_DATA,
                content_enc_alg: AlgorithmIdentifier {
                    oid: PBES2_OID,
                    parameters: Some(Any::from(der_cert_params_ref)),
                },
                encrypted_content: Some(OctetString::new(cert_ciphertext)?),
            },
            unprotected_attrs: None,
        };
        let der_enc_data1 = enc_data1.to_der()?;
        let der_data_ref1 = AnyRef::try_from(der_enc_data1.as_slice())?;

        let der_key_kdf_alg = match &self.key_kdf_algorithm_identifier {
            Some(key_kdf_alg) => match &key_kdf_alg.parameters {
                Some(params) => params.to_der()?,
                None => {
                    return Err(Error::Builder(String::from(
                        "No parameters provided for key KDF algorithm",
                    )))
                }
            },
            None => {
                return Err(Error::Builder(String::from(
                    "No key KDF algorithm provided",
                )))
            }
        };
        let key_kdf = Kdf::from(Pbkdf2Params::from_der(&der_key_kdf_alg)?);

        let der_key_enc_alg = match &self.key_enc_algorithm_identifier {
            Some(key_enc_alg) => key_enc_alg.to_der()?,
            None => {
                return Err(Error::Builder(String::from(
                    "No key encryption algorithm provided",
                )))
            }
        };
        let key_encryption = pbes2::EncryptionScheme::from_der(&der_key_enc_alg)?;

        let key_params = pbes2::Parameters {
            kdf: key_kdf,
            encryption: key_encryption,
        };
        let key_scheme = pkcs5::EncryptionScheme::from(key_params.clone());
        let mut enc_buf = key.to_vec();
        enc_buf.extend_from_slice(vec![0x00; 16].as_slice());
        let key_ciphertext = match key_scheme.encrypt_in_place(password, &mut enc_buf, key.len()) {
            Ok(ct) => ct,
            Err(e) => {
                return Err(Error::Builder(
                    format!("Failed to encrypt key: {e:?}").to_string(),
                ))
            }
        };

        // let der_key_params = key_params.to_der().unwrap();
        // let der_key_params_ref = AnyRef::try_from(der_key_params.as_slice()).unwrap();

        let enc_epki = EncryptedPrivateKeyInfo {
            encryption_algorithm: key_scheme,
            encrypted_data: key_ciphertext,
        };
        let der_enc_epki = enc_epki.to_der()?;

        let shrouded_key_bag = SafeBag {
            bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
            bag_value: der_enc_epki,
            bag_attributes: self.key_attributes.clone(),
        };
        let sb = vec![shrouded_key_bag];
        let der_enc_data2 = sb.to_der()?;
        let os2 = OctetString::new(der_enc_data2)?.to_der()?;
        let der_data_ref2 = AnyRef::try_from(os2.as_slice())?;

        let auth_safes = vec![
            ContentInfo {
                content_type: ID_ENCRYPTED_DATA,
                content: Any::from(der_data_ref1),
            },
            ContentInfo {
                content_type: ID_DATA,
                content: Any::from(der_data_ref2),
            },
        ];

        let content_bytes = auth_safes.to_der()?;
        let os = OctetString::new(content_bytes.clone())?.to_der()?;
        let content = AnyRef::try_from(os.as_slice())?;

        let auth_safe = ContentInfo {
            content_type: ID_DATA,
            content: Any::from(content),
        };

        let md_build = match &self.mac_data_builder {
            Some(md_build) => md_build,
            None => {
                return Err(Error::Builder(String::from(
                    "No MacData builder was provided",
                )))
            }
        };
        let mac_data = Some(md_build.build(password, &content_bytes)?);

        let pfx = Pfx {
            version: Version::V3,
            auth_safe,
            mac_data,
        };
        Ok(pfx.to_der()?)
    }
}

/// Adds an Attribute containing the provided key ID to the provided set of attributes.
pub fn add_key_id_attr(attrs: &mut SetOfVec<Attribute>, key_id: &[u8]) -> Result<()> {
    pub const PKCS_9_AT_LOCAL_KEY_ID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");

    let attr_bytes = OctetString::new(key_id)?.to_der()?;
    let attr_bytes_ref = AnyRef::try_from(attr_bytes.as_slice())?;
    let mut values = SetOfVec::new();
    values.insert(Any::from(attr_bytes_ref))?;
    let attr = Attribute {
        oid: PKCS_9_AT_LOCAL_KEY_ID,
        values,
    };
    Ok(attrs.insert(attr)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
fn check_algs(mac: &MacAlgorithm, enc: &EncryptionAlgorithm, kdf: &Pbkdf2Prf, der_p12: &[u8]) {
    use crate::asn1_utils::{get_auth_safes, get_safe_bags};
    use der::asn1::ContextSpecific;
    use pkcs5::pbes2::PBKDF2_OID;

    let pfx = Pfx::from_der(der_p12).unwrap();
    let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
    for auth_safe in auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            // certificate
            let enc_data = EncryptedData::from_der(&auth_safe.content.to_der().unwrap()).unwrap();
            assert_eq!(PBES2_OID, enc_data.enc_content_info.content_enc_alg.oid);

            let enc_params = enc_data
                .enc_content_info
                .content_enc_alg
                .parameters
                .as_ref()
                .unwrap()
                .to_der()
                .unwrap();
            let params = pbes2::Parameters::from_der(&enc_params).unwrap();
            assert_eq!(PBKDF2_OID, params.kdf.oid());
            assert_eq!(kdf.oid(), params.kdf.pbkdf2().unwrap().prf.oid());
            assert_eq!(enc.oid(), params.encryption.oid());
        } else if ID_DATA == auth_safe.content_type {
            // key
            let safe_bags = get_safe_bags(&auth_safe.content).unwrap();
            for safe_bag in safe_bags {
                match safe_bag.bag_id {
                    PKCS_12_PKCS8_KEY_BAG_OID => {
                        let cs: ContextSpecific<EncryptedPrivateKeyInfo<'_>> =
                            ContextSpecific::from_der(&safe_bag.bag_value).unwrap();
                        assert_eq!(PBES2_OID, cs.value.encryption_algorithm.oid());
                        assert_eq!(
                            kdf.oid(),
                            cs.value
                                .encryption_algorithm
                                .pbes2()
                                .unwrap()
                                .kdf
                                .pbkdf2()
                                .unwrap()
                                .prf
                                .oid()
                        );
                        assert_eq!(
                            enc.oid(),
                            cs.value
                                .encryption_algorithm
                                .pbes2()
                                .unwrap()
                                .encryption
                                .oid()
                        );
                    }
                    _ => {
                        panic!("Unexpected bag type");
                    }
                }
            }
        } else {
            panic!("Unexpected bag type");
        }
    }

    match pfx.mac_data {
        Some(mac_data) => {
            assert_eq!(mac.oid(), mac_data.mac.algorithm.oid);
        }
        None => {
            panic!("Missing MAC");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
fn check_with_openssl(password: &str, der_p12: &[u8]) {
    use openssl::pkcs12::Pkcs12;
    openssl::init();
    let pkcs12 = Pkcs12::from_der(der_p12).unwrap();
    let _p12 = pkcs12.as_ref().parse2(password).unwrap();
}

#[test]
#[allow(clippy::unwrap_used)]
fn p12_builder_combinations() {
    use rand_core::OsRng;

    let mac_algs = [
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ];
    let enc_algs = [
        EncryptionAlgorithm::Aes128Cbc,
        EncryptionAlgorithm::Aes192Cbc,
        EncryptionAlgorithm::Aes256Cbc,
    ];
    let kdf_algs = [
        Pbkdf2Prf::HmacWithSha256,
        Pbkdf2Prf::HmacWithSha384,
        Pbkdf2Prf::HmacWithSha512,
    ];

    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key =
        include_bytes!("/Users/cwallace/devel/RustCrypto/formats/pkcs12/tests/examples/key.der");
    let cert_bytes =
        include_bytes!("/Users/cwallace/devel/RustCrypto/formats/pkcs12/tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();
    let password = "password";

    // Spin over various combinations of algorithms...
    for mac in &mac_algs {
        for enc in &enc_algs {
            for kdf in &kdf_algs {
                let der_pfx = Pkcs12Builder::new()
                    .cert_enc_algorithm(Some(enc.clone()))
                    .key_enc_algorithm(Some(enc.clone()))
                    .cert_kdf_algorithm(Some(*kdf))
                    .key_kdf_algorithm(Some(*kdf))
                    .mac_data_builder(Some(MacDataBuilder::new(mac.clone())))
                    .key_attributes(Some(key_attrs.clone()))
                    .cert_attributes(Some(cert_attrs.clone()))
                    .build_with_rng(cert.clone(), key, password, &mut OsRng)
                    .unwrap();
                println!("{mac:?}-{enc:?}-{kdf:?}: {}", buffer_to_hex(&der_pfx));

                // use std::fs::File;
                // use std::io::Write;
                // let mut p12_file =
                //     File::create(format!("target/{mac:?}-{enc:?}-{kdf:?}.p12")).unwrap();
                // let _ = p12_file.write_all(&der_pfx);

                // Parse with pkcs12 crate and make sure algorithms match expectations
                check_algs(mac, enc, kdf, &der_pfx);

                // Make sure openssl can parse the results
                check_with_openssl(password, &der_pfx);
            }
        }
    }
}

#[cfg(test)]
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    std::str::from_utf8(&subtle_encoding::hex::encode_upper(buffer))
        .unwrap_or_default()
        .to_string()
}

#[test]
#[allow(clippy::unwrap_used)]
fn p12_builder_with_defaults_test() {
    use rand_core::OsRng;

    let mut p12_builder = Pkcs12Builder::new();
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("../examples/key.der");
    let cert_bytes = include_bytes!("../examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));

    let der_pfx = p12_builder
        .build_with_rng(cert, key, "", &mut OsRng)
        .unwrap();
    println!("{}", buffer_to_hex(&der_pfx));
}

#[test]
#[allow(clippy::unwrap_used)]
fn p12_builder_test() {
    use hex_literal::hex;

    let mut p12_builder = Pkcs12Builder::new();
    let key_id = hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    // Cert bag
    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();
    p12_builder.cert_attributes(Some(cert_attrs));

    let cert_kdf_params = Pbkdf2Params {
        salt: &hex!("9A A2 77 B5 F0 51 B4 50"),
        iteration_count: 2048,
        key_length: None,
        prf: Pbkdf2Prf::HmacWithSha256,
    };
    let enc_cert_kdf_params = cert_kdf_params.to_der().unwrap();
    let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice()).unwrap();
    let cert_kdf_alg = AlgorithmIdentifierOwned {
        oid: PBES2_OID,
        parameters: Some(Any::from(enc_cert_kdf_params_ref)),
    };
    p12_builder.cert_kdf_algorithm_identifier(Some(cert_kdf_alg));

    let cert_iv = OctetString::new(hex!("2E 23 6C 8C 7A 44 0C 3E 0F 4E 0D 32 C9 90 E9 97"))
        .unwrap()
        .to_der()
        .unwrap();
    let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice()).unwrap();
    p12_builder.cert_enc_algorithm_identifier(Some(AlgorithmIdentifier {
        oid: AES_256_CBC_OID,
        parameters: Some(Any::from(cert_iv_ref)),
    }));

    // Key bag
    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();
    p12_builder.key_attributes(Some(key_attrs));

    let key_kdf_params = Pbkdf2Params {
        salt: &hex!("10 AF 41 1E 77 84 BA CD"),
        iteration_count: 2048,
        key_length: None,
        prf: Pbkdf2Prf::HmacWithSha256,
    };
    let enc_key_kdf_params = key_kdf_params.to_der().unwrap();
    let enc_key_kdf_params_ref = AnyRef::try_from(enc_key_kdf_params.as_slice()).unwrap();
    let key_kdf_alg = AlgorithmIdentifierOwned {
        oid: PBES2_OID,
        parameters: Some(Any::from(enc_key_kdf_params_ref)),
    };
    p12_builder.key_kdf_algorithm_identifier(Some(key_kdf_alg));

    let key_iv = OctetString::new(hex!("46 21 13 61 4C 99 4D 1F DA 70 B4 71 16 5A AE 4A"))
        .unwrap()
        .to_der()
        .unwrap();
    let key_iv_ref = AnyRef::try_from(key_iv.as_slice()).unwrap();
    p12_builder.key_enc_algorithm_identifier(Some(AlgorithmIdentifier {
        oid: AES_256_CBC_OID,
        parameters: Some(Any::from(key_iv_ref)),
    }));

    // Mac
    let mut md_builder = MacDataBuilder::new(MacAlgorithm::HmacSha256);
    md_builder.iterations(Some(2048));
    md_builder.salt(Some(hex!("FF 08 ED 21 81 C8 A8 E3").to_vec()));
    p12_builder.mac_data_builder(Some(md_builder));

    let orig_p12 = include_bytes!("../examples/example.pfx");
    let key = include_bytes!("../examples/key.der");
    let cert_bytes = include_bytes!("../examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let der_pfx = p12_builder.build(cert, key, "").unwrap();
    assert_eq!(der_pfx, orig_p12)
}
