/*
cargo run -p test-async-ssh2-lite --features password -- 127.0.0.1:22 root

// - or -

cargo run -p test-async-ssh2-lite --features publickey -- 127.0.0.1:22 root
*/

use std::future::Future;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;

use anyhow::anyhow;
use async_compat::CompatExt;
use async_io::Async;
use async_ssh2_lite::AsyncSession;

pub fn input(query: &str) -> std::io::Result<String> {
    print!("{}", query);
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_owned())
}

type SshSession = AsyncSession<TcpStream>;

async fn ssh_auth<F, R>(addr: SocketAddr, auther: F) -> anyhow::Result<Arc<SshSession>>
where
    F: FnOnce(Arc<SshSession>) -> R,
    R: Future<Output = anyhow::Result<()>>,
{
    let stream = Async::<TcpStream>::connect(addr).await?;
    let mut session = AsyncSession::new(stream, None)?;
    session.handshake().await?;

    let session = Arc::new(session);

    auther(session.clone()).await?;

    if !session.authenticated() {
        return Err(session
            .last_error()
            .map(Into::into)
            .unwrap_or_else(|| anyhow!("unknown userauth error")));
    }

    Ok(session)
}

async fn ssh_auth_by_pk(addr: SocketAddr, username: String) -> anyhow::Result<Arc<SshSession>> {
    ssh_auth(addr, move |session| async move {
        let mut agent = session.agent()?;
        agent.connect().await?;

        let publickey = input("Paste the public key for this user: ")?;

        agent.list_identities().await?;

        let user_identity = sshkeys::PublicKey::from_string(&publickey)?.encode();
        let identity = agent
            .identities()?
            .into_iter()
            .find(|identity| user_identity == identity.blob())
            .ok_or_else(|| anyhow!("failed to match an authenticated identity"))?;

        agent.userauth(&username, &identity).await?;

        Ok(())
    })
    .await
}

async fn ssh_auth_by_pass(addr: SocketAddr, username: String) -> anyhow::Result<Arc<SshSession>> {
    ssh_auth(addr, move |session| async move {
        let password = input("Enter the password for this user: ")?;
        session.userauth_password(&username, &password).await?;

        Ok(())
    })
    .await
}

async fn ssh_run<F: Future<Output = anyhow::Result<Arc<SshSession>>>>(
    session: F,
) -> anyhow::Result<()> {
    let session = session.await?;
    let mut channel = session.channel_session().await?;

    channel.exec(CMD).await?;

    let mut self_stdin = tokio::io::stdin();
    let mut self_stdout = tokio::io::stdout();
    let mut self_stderr = tokio::io::stderr();

    let mut remote_stdin = channel.stream(0).compat();
    let mut remote_stdout = channel.stream(0).compat();
    let mut remote_stderr = channel.stream(1).compat();

    println!("============================");
    let stdin_proc = tokio::io::copy(&mut self_stdin, &mut remote_stdin);
    let stdout_proc = tokio::io::copy(&mut remote_stdout, &mut self_stdout);
    let stderr_proc = tokio::io::copy(&mut remote_stderr, &mut self_stderr);

    let stdio = async { tokio::try_join!(stdin_proc, stdout_proc, stderr_proc) };

    tokio::select! {
        r = stdio => { r?; },
        r = channel.wait_eof().compat() => { r?; }
    }
    println!("============================");

    channel.close().await?;
    channel.wait_close().await?;
    println!(
        "\x1b[36mThe process exited with code {}\x1b[0m",
        channel.exit_status()?
    );
    Ok(())
}

fn parse_addr(addr: &str) -> anyhow::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| unreachable!("oops, took a wrong turn"))
}

const CMD: &str = r#"{
    for _ in {1..5}; do
        echo "\x1b[33mstderr: hello\x1b[0m" > /dev/stderr;
        echo "\x1b[34mstdout: world\x1b[0m" > /dev/stdout;
        sleep .1
    done
}"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:22".to_owned());

    let addr = parse_addr(&addr)?;

    let username = std::env::args().nth(2).unwrap_or_else(|| "root".to_owned());

    if cfg!(all(
        any(feature = "publickey", feature = "password"),
        not(all(feature = "publickey", feature = "password"))
    )) {
        if cfg!(feature = "publickey") {
            if let Err(err) = ssh_run(ssh_auth_by_pk(addr, username)).await {
                println!("{:?}", err);
            }
        } else if cfg!(feature = "password") {
            if let Err(err) = ssh_run(ssh_auth_by_pass(addr, username)).await {
                println!("{:?}", err);
            }
        }

        return Ok(());
    }

    println!("please specify --features with *either* `publickey` or `password`");
    std::process::exit(1);
}
