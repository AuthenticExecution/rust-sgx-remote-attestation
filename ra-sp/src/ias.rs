use crate::attestation_response::AttestationResponse;
use crate::error::{AttestationError, IasError};
use ra_common::msg::{Gid, Quote};
use sgx_crypto::certificate::X509Cert;
use std::io::Write;
use std::sync::Arc;
use anyhow::Result;

use std::net::TcpStream;

use sgx_crypto::Rng;
use sgx_crypto::mbedtls::ssl::config::{Endpoint, Preset, Transport};
use sgx_crypto::mbedtls::ssl::{Config, Context};
use sgx_crypto::mbedtls::x509::Certificate;
use sgx_crypto::mbedtls::alloc::List;

use http_bytes::http::Request;
use std::io::Read;

const ADDRESS : & str = "api.trustedservices.intel.com:443";
const BASE_URI: &str = "https://api.trustedservices.intel.com/sgx/dev";
const SIG_RL_PATH: &str = "/attestation/v3/sigrl/";
const REPORT_PATH: &str = "/attestation/v3/report";

const CERT: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAw
MjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy
dGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B
3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkY
tJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+bJz/
Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2
VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT
79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6
c0Plfg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmT
Yo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97l
c6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4ee
UB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeE
Hg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd
BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8G
A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPF
Up/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KO
VWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3
ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs
8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR
iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYze
Sf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZ
XHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/
qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRB
VXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGwsAvgnEzDHNb842m1R0aB
L6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfG
jjxDah2nGN59PRbxYvnKkKj9
-----END CERTIFICATE-----
\0";

pub struct IasClient {
    root_ca_cert: X509Cert,
    ctx: Context
}

impl IasClient {
    pub fn new(root_ca_cert: X509Cert) -> Result<Self> {
        let cert = Certificate::from_pem(CERT)?;
        let mut list = List::new();
        list.push(cert);
        let rng = Arc::new(Rng);
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(rng);
        config.set_ca_list(Arc::new(list), None);
        let mut ctx = Context::new(Arc::new(config));

        let conn = TcpStream::connect(ADDRESS)?;
        ctx.establish(conn, None)?;

        Ok(Self {
            root_ca_cert,
            ctx
        })
    }

    pub fn get_sig_rl(
        &mut self,
        gid: &Gid,
        subscription_key: &str,
    ) -> Result<Option<Vec<u8>>> {
        let uri = format!(
            "{}{}{:02x}{:02x}{:02x}{:02x}",
            BASE_URI, SIG_RL_PATH, gid[0], gid[1], gid[2], gid[3]
        );
        let req = Request::get(uri)
            .header("Ocp-Apim-Subscription-Key", subscription_key)
            .body(())?;

        http_bytes::write_request_header(&req, &mut self.ctx)?;

        //TODO check size of this buffer
        let mut buf = [0u8;1024*10];
        let n = self.ctx.read(&mut buf)?;
        let (header, body) = match http_bytes::parse_response_header_easy(&buf[..n])? {
            Some(r) => r,
            None    => return Err(IasError::BufferTooSmall.into())
        };

        if header.status().as_u16() != 200 {
            return Err(IasError::SigRLError(header.status()).into());
        }
        if header.headers().get("content-length").ok_or(AttestationError::BadHeader)? == "0" {
            return Ok(None);
        }
        let mut sig_rl = Vec::new();
        sig_rl.write_all(&body)?;

        Ok(Some(sig_rl))
    }

    pub fn verify_attestation_evidence(
        &mut self,
        quote: &Quote,
        subscription_key: &str,
    ) -> Result<AttestationResponse> {
        let uri = format!("{}{}", BASE_URI, REPORT_PATH);
        let quote_base64 = base64::encode(&quote[..]);
        let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}", quote_base64);

        let req = Request::post(uri)
            .header("Content-type", "application/json")
            .header("Ocp-Apim-Subscription-Key", subscription_key)
            .header("Content-Length", body.len())
            .body(&body)?;

        http_bytes::write_request_header(&req, &mut self.ctx)?;
        self.ctx.write(body.as_bytes())?;

        //TODO check size of this buffer
        let mut buf = [0u8;1024*10];
        let n = self.ctx.read(&mut buf)?;
        let (header, resp_body) = match http_bytes::parse_response_header_easy(&buf[..n])? {
            Some(r) => r,
            None    => return Err(IasError::BufferTooSmall.into())
        };

        if header.status().as_u16() != 200 {
            return Err(IasError::Attestation(AttestationError::Connection(
                header.status(),
            )).into());
        }

        let mut body = Vec::new();
        body.write_all(&resp_body)?;

        AttestationResponse::from_response(&self.root_ca_cert, header.headers(), body)
    }
}
