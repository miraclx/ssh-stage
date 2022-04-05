use std::future::Future;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_compat::CompatExt;
use async_io::Async;
use async_ssh2::AsyncSession;

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

fn parse_addr(addr: &str) -> anyhow::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| unreachable!("oops, took a wrong turn"))
}

async fn ssh_auth<'a, F, R>(auther: F) -> anyhow::Result<Arc<SshState>>
where
    F: Fn(Arc<SshState>) -> R,
    R: Future<Output = anyhow::Result<()>> + 'a,
{
    let addr = input("Enter the host address (e.g: localhost:22): ")?;
    let addr = parse_addr(&addr).context("no valid addresses found")?;

    let stream = Async::<TcpStream>::connect(addr).await?;
    let mut session = AsyncSession::new(stream, None)?;
    session.handshake().await?;

    let username = input("Enter a username to authorize: ")?;

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

async fn ssh_auth_by_pk() -> anyhow::Result<Arc<SshState>> {
    ssh_auth(|state| async move {
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

async fn ssh_auth_by_pass() -> anyhow::Result<Arc<SshState>> {
    ssh_auth(|state| async move {
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

    channel.close().await?;
    channel.wait_close().await?;
    println!("============================");
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
async fn main() {
    if cfg!(all(
        any(feature = "publickey", feature = "password"),
        not(all(feature = "publickey", feature = "password"))
    )) {
        if cfg!(feature = "publickey") {
            match ssh_run(ssh_auth_by_pk()).await {
                Err(err) => println!("{:?}", err),
                _ => {}
            };
        } else if cfg!(feature = "password") {
            match ssh_run(ssh_auth_by_pass()).await {
                Err(err) => println!("{:?}", err),
                _ => {}
            }
        }

        return;
    }

    println!("please specify --features with *either* publickey or password");
    std::process::exit(1);
}
