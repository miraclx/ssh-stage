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

struct SshState {
    session: AsyncSession<TcpStream>,
    username: String,
}

async fn ssh_auth<F, R>(
    addr: SocketAddr,
    username: String,
    auther: F,
) -> anyhow::Result<Arc<SshState>>
where
    F: Fn(Arc<SshState>) -> R,
    R: Future<Output = anyhow::Result<()>>,
{
    let stream = Async::<TcpStream>::connect(addr).await?;
    let mut session = AsyncSession::new(stream, None)?;
    session.handshake().await?;

    let state = Arc::new(SshState { session, username });

    auther(state.clone()).await?;

    if !state.session.authenticated() {
        return Err(state
            .session
            .last_error()
            .map(Into::into)
            .unwrap_or(anyhow!("unknown userauth error")));
    }

    Ok(state)
}

async fn ssh_auth_by_pk(addr: SocketAddr, username: String) -> anyhow::Result<Arc<SshState>> {
    ssh_auth(addr, username, |state| async move {
        let SshState { session, username } = &*state;
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

async fn ssh_auth_by_pass(addr: SocketAddr, username: String) -> anyhow::Result<Arc<SshState>> {
    ssh_auth(addr, username, |state| async move {
        let SshState { session, username } = &*state;
        let password = input("Enter the password for this user: ")?;
        session.userauth_password(username, &password).await?;

        Ok(())
    })
    .await
}

async fn ssh_run<F: Future<Output = anyhow::Result<Arc<SshState>>>>(
    state: F,
) -> anyhow::Result<()> {
    let SshState { session, .. } = &*state.await?;
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

    tokio::try_join!(stdin_proc, stdout_proc, stderr_proc)?;
    println!("============================");

    channel.close().await?;
    channel.wait_close().await?;
    println!(
        "\x1b[36mThe process exited with code {}\x1b[0m",
        channel.exit_status()?
    );
    Ok(())
}

const CMD: &'static str = r#"{
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
            match ssh_run(ssh_auth_by_pk(addr, username)).await {
                Err(err) => println!("{:?}", err),
                _ => {}
            };
        } else if cfg!(feature = "password") {
            match ssh_run(ssh_auth_by_pass(addr, username)).await {
                Err(err) => println!("{:?}", err),
                _ => {}
            }
        }

        return Ok(());
    }

    println!("please specify --features with *either* publickey or password");
    std::process::exit(1);
}

fn parse_addr(addr: &str) -> anyhow::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| unreachable!("oops, took a wrong turn"))
}
