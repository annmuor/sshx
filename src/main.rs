use {
    log::{info},
    pty_process::{OwnedWritePty, Pty},
    rand::random,
    russh::{
        server::{Auth, Handler, Msg, Response, Server, Session},
        Channel, ChannelId, CryptoVec, MethodSet,
    },
    russh_keys::key::{KeyPair, PublicKey},
    std::{
        collections::HashMap, net::SocketAddr, sync::Arc, time::Duration,
    },
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        spawn,
        sync::Mutex,
    },
    totp_lite::Sha512,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::try_init()?;
    let config = russh::server::Config {
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![KeyPair::generate_ed25519().unwrap()],
        ..Default::default()
    };
    let mut server = S;

    server
        .run_on_address(Arc::new(config), ("0.0.0.0", 2222))
        .await
        .unwrap();
    Ok(())
}

struct S;

impl Server for S {
    type Handler = App;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        App {
            ptys: Default::default(),
            channels: Default::default(),
        }
    }
}

struct App {
    ptys: Arc<Mutex<HashMap<ChannelId, Option<OwnedWritePty>>>>,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

static GEN_STR: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn gen_key() -> String {
    let mut s = String::new();
    // ascii-table is
    for _ in 0..32 {
        s.push(char::from(GEN_STR[random::<usize>() % GEN_STR.len()]));
    }
    s
}

#[async_trait::async_trait]
impl Handler for App {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::TOTP),
        })
    }

    async fn auth_totp(
        &mut self,
        user: &str,
        totp: Option<(&str, &str)>,
    ) -> Result<Auth, Self::Error> {
        if user.ne("adm1n") {
            return Ok(Auth::Reject {
                proceed_with_methods: None,
            });
        }
        Ok(match totp {
            None => Auth::TOTP {
                key: gen_key(),
                comment: "Please enter TOTP value based on this key and known secret".to_string(),
            },
            Some((secret, provided)) => {
                let right_key = totp_lite::totp_custom::<Sha512>(3600, 10, secret.as_bytes(), 0);
                match right_key.eq(provided) {
                    true => {
                        info!("Accepted TOTP auth for {user}");
                        Auth::Accept
                    }
                    false => {
                        if provided.len() != 10 {
                            Auth::TOTP {
                                key: gen_key(),
                                comment: "Wrong answer. Use new key. Enter 10 digits".to_string(),
                            }
                        } else {
                            Auth::TOTP {
                                key: gen_key(),
                                comment: "Wrong answer. Use new key. Try harder.".to_string(),
                            }
                        }
                    }
                }
            }
        })
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::TOTP),
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::TOTP),
        })
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::TOTP),
        })
    }

    async fn auth_keyboard_interactive(
        &mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<Response<'async_trait>>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::TOTP),
        })
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, _: &mut Session) -> Result<bool, Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(Some(ref mut w)) = self.ptys.lock().await.get_mut(&channel) {
            if w.write(data).await.is_err() {
                _session.close(channel);
            }
        } else {
            _session.close(channel);
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Starting shell for user");
        let mut cmd = pty_process::Command::new("bash");
        let pty = Pty::new()?;
        cmd.uid(99).gid(99)
            .arg0("bash")
            .env("FLAG", "WGCTF{1_l0v3_77h_pr0t0}")
            .spawn(&pty.pts()?)?;
        let (mut read, write) = pty.into_split();
        self.ptys.lock().await.insert(channel, Some(write));
        let mut buf = Box::new([0u8; 1024]);
        let _channels = self.channels.clone();
        spawn(async move {
            loop {
                if let Ok(len) = read.read(buf.as_mut_slice()).await {
                    if let Some(chan) = _channels.lock().await.get_mut(&channel) {
                        let _ = chan.make_writer().write(&buf.as_slice()[..len]).await;
                    } else {
                        break;
                    }
                } else {
                    if let Some(chan) = _channels.lock().await.get_mut(&channel) {
                        let _ = chan.close().await;
                        let _ = chan.make_writer().flush().await;
                    }
                    break;
                }
            }
        });
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("exec_request: {}", String::from_utf8_lossy(data));
        session.data(
            channel,
            CryptoVec::from_slice(b"exec_request denied. Use shell instead\n"),
        );
        session.close(channel);
        Ok(())
    }
}
