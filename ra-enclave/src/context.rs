use crate::error::EnclaveRaError;
use crate::local_attestation;
use ra_common::derive_secret_keys;
use ra_common::msg::{Quote, RaMsg2, RaMsg3, RaMsg4};
use sgx_crypto::cmac::{Cmac, MacTag};
use sgx_crypto::digest::sha256;
use sgx_crypto::key_exchange::OneWayAuthenticatedDHKE;
use sgx_crypto::Rng;
use sgx_crypto::signature::VerificationKey;
use sgx_isa::{Report, Targetinfo};
use std::io::{Read, Write};
use std::mem::size_of;
use anyhow::Result;

pub struct EnclaveRaContext {
    pub key_exchange: Option<OneWayAuthenticatedDHKE>,
    pub sp_vkey: VerificationKey,
}

impl EnclaveRaContext {
    pub fn init(sp_vkey_pem: &str) -> Result<Self> {
        let mut rng = Rng;
        let key_exchange = OneWayAuthenticatedDHKE::generate_keypair(&mut rng)?;
        Ok(Self {
            sp_vkey: VerificationKey::new(sp_vkey_pem.as_bytes())?,
            key_exchange: Some(key_exchange),
        })
    }

    pub fn do_attestation(
        mut self,
        mut client_stream: &mut (impl Read + Write),
    ) -> Result<(MacTag, MacTag)> {
        let (sk, mk) = self.process_msg_2(client_stream)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG2 processed");
        }

        let msg4: RaMsg4 = bincode::deserialize_from(&mut client_stream)?;
        if !msg4.is_enclave_trusted {
            return Err(EnclaveRaError::EnclaveNotTrusted.into());
        }
        match msg4.is_pse_manifest_trusted {
            Some(t) => {
                if !t {
                    return Err(EnclaveRaError::PseNotTrusted.into());
                }
            }
            None => {}
        }
        if cfg!(feature = "verbose") {
            eprintln!("Attestation succeeded");
        }
        Ok((sk, mk))
    }

    // Return (signing key, master key)
    pub fn process_msg_2(
        &mut self,
        mut client_stream: &mut (impl Read + Write),
    ) -> Result<(MacTag, MacTag)> {
        let g_a = self.key_exchange.as_ref().unwrap().get_public_key()?; // safe unwrap
        bincode::serialize_into(&mut client_stream, &g_a)?;
        client_stream.flush()?;

        let msg2: RaMsg2 = bincode::deserialize_from(&mut client_stream)?;

        if cfg!(feature = "verbose") {
            eprintln!("MSG2 received");
        }

        // Verify and derive KDK and then other secret keys
        let mut rng = Rng;
        let kdk = self
            .key_exchange
            .take()
            .unwrap() // safe unwrap
            .verify_and_derive(&msg2.g_b, &msg2.sign_gb_ga, &mut self.sp_vkey, &mut rng)?;
        let mut kdk_cmac = Cmac::new(&kdk)?;
        let (smk, sk, mk, vk) = derive_secret_keys(&mut kdk_cmac)?;
        let mut smk = Cmac::new(&smk)?;

        if cfg!(feature = "verbose") {
            eprintln!("KDK verified");
        }

        // Verify MAC tag of MSG2
        msg2.verify_mac(&mut smk)?;

        if cfg!(feature = "verbose") {
            eprintln!("MSG2 MAC verified");
        }

        // Obtain SHA-256(g_a || g_b || vk)
        let mut verification_msg = Vec::new();
        verification_msg.write_all(g_a.as_ref())?;
        verification_msg.write_all(&msg2.g_b)?;
        verification_msg.write_all(&vk)?;
        let verification_digest = sha256(&verification_msg[..])?;

        // Obtain Quote
        if cfg!(feature = "verbose") {
            eprintln!("Getting quote from aesm-client");
        }

        let quote = Self::get_quote(&verification_digest[..], client_stream)?;

        if cfg!(feature = "verbose") {
            eprintln!("Quote obtained");
        }

        // Send MAC for msg3 to client
        let msg3 = RaMsg3::new(&mut smk, g_a, None, quote)?;
        client_stream.write_all(&msg3.mac)?;
        client_stream.flush()?;

        if cfg!(feature = "verbose") {
            eprintln!("MSG3 sent");
        }

        Ok((sk, mk))
    }

    /// Get quote from Quote Enclave. The length of report_data must be <= 64 bytes.
    pub fn get_quote(
        report_data: &[u8],
        client_stream: &mut (impl Read + Write),
    ) -> Result<Quote> {
        if report_data.len() > 64 {
            return Err(EnclaveRaError::ReportDataLongerThan64Bytes.into());
        }

        // Obtain QE's target info to build a report for local attestation.
        // Then, send the report back to client.
        let mut _report_data = [0u8; 64];
        (&mut _report_data[..(report_data.len())]).copy_from_slice(report_data);
        let mut target_info = [0u8; Targetinfo::UNPADDED_SIZE];
        client_stream.read_exact(&mut target_info)?;
        let target_info = Targetinfo::try_copy_from(&target_info).ok_or(EnclaveRaError::TargetinfoError)?;
        let report = Report::for_target(&target_info, &_report_data);
        client_stream.write_all(report.as_ref())?;
        client_stream.flush()?;

        // Obtain quote and QE report from client
        let mut quote = [0u8; size_of::<Quote>()];
        client_stream.read_exact(&mut quote[..])?;
        let qe_report_len = 432usize;
        let mut qe_report = vec![0u8; qe_report_len];
        client_stream.read_exact(&mut qe_report[..])?;

        // Verify that the report is generated by QE
        local_attestation::verify_local_attest(&qe_report[..])
            .map_err(|e| EnclaveRaError::LocalAttestation(e))?;
        Ok(quote)
    }
}
