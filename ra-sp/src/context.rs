use crate::config::SpConfig;
use crate::error::SpRaError;
use crate::ias::IasClient;
use crate::AttestationResult;
use byteorder::{LittleEndian, ReadBytesExt};
use ra_common::derive_secret_keys;
use ra_common::msg::{RaMsg0, RaMsg1, RaMsg2, RaMsg3, RaMsg4, Spid};
use sgx_crypto::certificate::X509Cert;
use sgx_crypto::cmac::{Cmac, MacTag};
use sgx_crypto::digest::{sha256, Sha256Digest};
use sgx_crypto::key_exchange::{DHKEPublicKey, OneWayAuthenticatedDHKE};
use sgx_crypto::Rng;
use sgx_crypto::signature::SigningKey;
use sgxs::sigstruct;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use anyhow::Result;

pub struct SpRaContext {
    config: SpConfig,
    sigstruct: sigstruct::Sigstruct,
    ias_client: IasClient,
    sp_private_key: SigningKey,
    rng: Rng,
    key_exchange: Option<OneWayAuthenticatedDHKE>,
    g_a: Option<DHKEPublicKey>,
    verification_digest: Option<Sha256Digest>,
    smk: Option<Cmac>,
    sk_mk: Option<(MacTag, MacTag)>,
}

impl SpRaContext {
    pub fn init(mut config: SpConfig) -> Result<Self> {
        assert!(config.linkable, "Only Linkable Quote supported");
        assert!(!config.random_nonce, "Random nonces not supported");
        assert!(
            !config.use_platform_service,
            "Platform service not supported"
        );
        if cfg!(feature = "verbose") {
            eprintln!("==================SP Config==================");
            eprintln!("{:#?}", config);
            eprintln!("=============================================");
        }

        assert!(!config.spid.is_empty());
        assert!(!config.primary_subscription_key.is_empty());

        // Preparing for binary search
        config.quote_trust_options.sort();
        config.pse_trust_options.as_mut().map(|v| v.sort());

        let sp_private_key =
            SigningKey::new_from_file(Path::new(&config.sp_private_key_pem_path), None)?;

        let cert = X509Cert::new_from_pem_file(Path::new(&config.ias_root_cert_pem_path))?;

        let mut rng = Rng;
        let key_exchange = OneWayAuthenticatedDHKE::generate_keypair(&mut rng)?;

        let mut sigstruct = File::open(Path::new(&config.sigstruct_path))?;
        let sigstruct = sigstruct::read(&mut sigstruct)?;

        Ok(Self {
            config,
            sigstruct,
            ias_client: IasClient::new(cert)?,
            sp_private_key,
            rng,
            key_exchange: Some(key_exchange),
            g_a: None,
            verification_digest: None,
            smk: None,
            sk_mk: None,
        })
    }

    pub fn init_from(mut config: SpConfig, sigstruct : sigstruct::Sigstruct, sp_private_key : SigningKey, cert : X509Cert) -> Result<SpRaContext> {
        if !config.linkable {
            return Err(SpRaError::InvalidSpConfig(String::from("Only Linkable Quote supported")).into())
        }

        if config.random_nonce {
            return Err(SpRaError::InvalidSpConfig(String::from("Random nonces not supported")).into())
        }

        if config.use_platform_service {
            return Err(SpRaError::InvalidSpConfig(String::from("Platform service not supported")).into())
        }

        if config.spid.is_empty() {
            return Err(SpRaError::InvalidSpConfig(String::from("spid field is empty")).into())
        }

        if config.primary_subscription_key.is_empty() {
            return Err(SpRaError::InvalidSpConfig(String::from("primary_subscription_key field is empty")).into())
        }

        // Preparing for binary search
        config.quote_trust_options.sort();
        config.pse_trust_options.as_mut().map(|v| v.sort());

        let mut rng = Rng;
        let key_exchange = OneWayAuthenticatedDHKE::generate_keypair(&mut rng)?;

        Ok(SpRaContext {
            config,
            sigstruct,
            ias_client: IasClient::new(cert)?,
            sp_private_key,
            rng,
            key_exchange: Some(key_exchange),
            g_a: None,
            verification_digest: None,
            smk: None,
            sk_mk: None,
        })
    }

    pub fn do_attestation(
        mut self,
        mut client_stream: &mut (impl Read + Write),
    ) -> Result<AttestationResult> {
        // Not using MSG0 for now.
        let _msg0: RaMsg0 = bincode::deserialize_from(&mut client_stream)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG0 received ");
        }

        let msg1: RaMsg1 = bincode::deserialize_from(&mut client_stream)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG1 received");
        }

        let msg2 = self.process_msg_1(msg1)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG1 processed");
        }

        bincode::serialize_into(&mut client_stream, &msg2)?;
        client_stream.flush()?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG2 sent");
        }

        let msg3: RaMsg3 = bincode::deserialize_from(&mut client_stream)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG3 received");
        }

        let (msg4, epid_pseudonym) = self.process_msg_3(msg3)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG4 generated");
        }

        bincode::serialize_into(&mut client_stream, &msg4)?;
        client_stream.flush()?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG4 sent");
        }

        if !msg4.is_enclave_trusted {
            return Err(SpRaError::EnclaveNotTrusted.into());
        }
        match msg4.is_pse_manifest_trusted {
            Some(t) => {
                if !t {
                    return Err(SpRaError::EnclaveNotTrusted.into());
                }
            }
            None => {}
        }

        let (signing_key, master_key) = self.sk_mk.take().
            ok_or(SpRaError::GenericError(String::from("sk_mk empty")))?;

        Ok(AttestationResult {
            epid_pseudonym,
            signing_key,
            master_key,
        })
    }

    pub fn process_msg_1(&mut self, msg1: RaMsg1) -> Result<RaMsg2> {
        // Get sigRL
        let sig_rl = self
            .ias_client
            .get_sig_rl(&msg1.gid, &self.config.primary_subscription_key)?;

        let key_exchange = self.key_exchange.take()
            .ok_or(SpRaError::GenericError(String::from("key_exchange empty")))?;
        let g_b = key_exchange.get_public_key()?;

        // Sign and derive KDK and other secret keys
        let (kdk, sign_gb_ga) =
            key_exchange.sign_and_derive(&msg1.g_a, &mut self.sp_private_key, &mut self.rng)?;
        let mut kdk_cmac = Cmac::new(&kdk)?;
        let (smk, sk, mk, vk) = derive_secret_keys(&mut kdk_cmac)?;
        let smk = Cmac::new(&smk)?;

        // Obtain SHA-256(g_a || g_b || vk)
        let mut verification_msg = Vec::new();
        verification_msg.write_all(&msg1.g_a)?;
        verification_msg.write_all(&g_b[..])?;
        verification_msg.write_all(&vk)?;
        let verification_digest = sha256(&verification_msg[..])?;

        // Set context
        self.smk = Some(smk);
        self.sk_mk = Some((sk, mk));
        self.verification_digest = Some(verification_digest);
        self.g_a = Some(msg1.g_a.clone());

        let spid: Spid = hex::decode(&self.config.spid)?
            .as_slice()
            .try_into()?;
        let quote_type = self.config.linkable as u16;

        Ok(RaMsg2::new(
            self.smk.as_mut().ok_or(SpRaError::GenericError(String::from("smk empty")))?,
            g_b,
            spid,
            quote_type,
            sign_gb_ga,
            sig_rl,
        )?)
    }

    pub fn process_msg_3(&mut self, msg3: RaMsg3) -> Result<(RaMsg4, Option<String>)> {
        // Integrity check
        if &msg3.g_a[..] != &self.g_a.as_ref().ok_or(SpRaError::GenericError(String::from("g_a empty")))?[..] {
            return Err(SpRaError::IntegrityError.into());
        }
        if !msg3.verify_mac(self.smk.as_mut().ok_or(SpRaError::GenericError(String::from("smk empty")))?).is_ok() {
            return Err(SpRaError::IntegrityError.into());
        }

        let quote_digest: Sha256Digest = (&msg3.quote.as_ref()[368..400]).try_into()?;
        if self.verification_digest.as_ref()
            .ok_or(SpRaError::GenericError(String::from("verification_digest empty")))? != &quote_digest {
            return Err(SpRaError::IntegrityError.into());
        }

        // Verify attestation evidence
        // TODO: use the secondary key as well
        let attestation_result = self
            .ias_client
            .verify_attestation_evidence(&msg3.quote, &self.config.primary_subscription_key)?;

        if cfg!(feature = "verbose") {
            eprintln!("==============Attestation Result==============");
            eprintln!("{:#?}", attestation_result);
            eprintln!("==============================================");
        }

        // Verify enclave identity
        let mrenclave = &msg3.quote[112..144];
        let mrsigner = &msg3.quote[176..208];
        let isvprodid = (&msg3.quote[304..306]).read_u16::<LittleEndian>()?;
        let isvsvn = (&msg3.quote[306..308]).read_u16::<LittleEndian>()?;
        if mrenclave != self.sigstruct.enclavehash.as_ref()
            || mrsigner != sha256(self.sigstruct.modulus.as_ref())?.as_ref()
            || isvprodid != self.sigstruct.isvprodid
            || isvsvn != self.sigstruct.isvsvn
        {
            return Err(SpRaError::SigstructMismatched.into());
        }

        // Make sure the enclave is not in debug mode in production
        let attribute_flags = &self.sigstruct.attributes.flags;
        if cfg!(not(debug_assertions)) {
            if (&sgx_isa::AttributesFlags::DEBUG).intersects(*attribute_flags) {
                //return Err(SpRaError::EnclaveInDebugMode);
                eprintln!("WARNING: Enclave is running in debug mode. Do not trust this enclave in production.")
            }
        } else {
            eprintln!("WARNING: Enclave is running in debug mode. Do not trust this enclave in production.")
        }

        // Decide whether to trust enclave
        let quote_status = attestation_result.isv_enclave_quote_status.clone();
        let pse_manifest_status = attestation_result.pse_manifest_status.clone();
        let is_enclave_trusted = (quote_status == "OK")
            || self
                .config
                .quote_trust_options
                .binary_search(&quote_status)
                .is_ok();
        let is_pse_manifest_trusted = pse_manifest_status.map(|status| {
            (status == "OK")
                || self
                    .config
                    .pse_trust_options
                    .as_ref()
                    .unwrap() // safe unwrap
                    .binary_search(&status)
                    .is_ok()
        });

        Ok((
            RaMsg4 {
                is_enclave_trusted,
                is_pse_manifest_trusted,
                pib: attestation_result.platform_info_blob,
            },
            attestation_result.epid_pseudonym,
        ))
    }
}
