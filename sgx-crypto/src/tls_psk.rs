use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::ssl::context::HandshakeContext;
use mbedtls::Result;
use std::sync::Arc;
use std::net::TcpStream;

use super::Rng;

pub type Callback = Box<dyn FnMut(&mut HandshakeContext, &str) -> Result<()>>;

pub fn new_server_context(
    psk: &[u8; 16],
    conn : TcpStream
) -> Result<Context<TcpStream>> {
    let rng = Arc::new(Rng);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_psk(psk, "client")?;
    let mut ctx = Context::new(Arc::new(config));
    ctx.establish(conn, None)?;

    Ok(ctx)
}

pub fn new_client_context(
    psk: &[u8; 16],
    conn : TcpStream
) -> Result<Context<TcpStream>> {
    let rng = Arc::new(Rng);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_psk(psk, "client")?;
    let mut ctx = Context::new(Arc::new(config));
    ctx.establish(conn, None)?;

    Ok(ctx)
}
