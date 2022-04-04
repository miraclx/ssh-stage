use std::io::{self, Read, Write};

use anyhow::{anyhow, bail, Context};

pub fn input(query: &str) -> io::Result<String> {
    print!("{}", query);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_owned())
}

struct State<'a> {
    session: &'a ssh2::Session,
    agent: &'a mut ssh2::Agent,
    username: &'a str,
}

fn ssh<F: Fn(State) -> anyhow::Result<()>>(auther: F) -> anyhow::Result<()> {
    let addr = input("Enter the host address (e.g: localhost:22): ")?;
    let tcp = std::net::TcpStream::connect(addr)?;
    let mut sess = ssh2::Session::new().context("failed to initialize an SSH session")?;
    sess.set_tcp_stream(tcp);
    sess.handshake()
        .context("failed to connect to the SSH session")?;

    let mut agent = sess.agent().context("sess.agent()")?;

    agent.connect().context("agent.connect()")?;

    let username = input("Enter a username to authorize: ")?;

    auther(State {
        session: &sess,
        agent: &mut agent,
        username: &username,
    })?;

    if !sess.authenticated() {
        bail!("authentication failure")
    }

    let mut channel = sess.channel_session()?;

    channel.exec("ls")?;

    let mut buf = [0; 0x4000];
    let mut self_stdout = io::stdout().lock();
    let mut proc_stdout = channel.stream(0);
    while let Ok(n) = proc_stdout.read(&mut buf) {
        if n == 0 {
            break;
        }
        self_stdout.write(&buf[..n])?;
    }
    channel.wait_close()?;
    println!("{}", channel.exit_status()?);

    Ok(())
}

fn ssh_auth_by_pk() -> anyhow::Result<()> {
    ssh(|state| {
        let State {
            agent, username, ..
        } = state;
        let publickey = input("Paste the public key for this user: ")?;

        agent.list_identities().context("agent.list_identities()")?;

        let user_identity = sshkeys::PublicKey::from_string(&publickey)?.encode();
        let identity = agent
            .identities()?
            .into_iter()
            .find(|identity| user_identity == identity.blob())
            .ok_or_else(|| anyhow!("failed to match an authenticated identity"))?;

        agent
            .userauth(&username, &identity)
            .context("agent.userauth()")?;

        Ok(())
    })
}
fn ssh_auth_by_pass() -> anyhow::Result<()> {
    ssh(|state| {
        let State {
            session, username, ..
        } = state;
        let password = input("Enter the password for this user: ")?;
        session.userauth_password(username, &password)?;

        Ok(())
    })
}

fn main() {
    match ssh_auth_by_pk() {
        Err(err) => println!("{:?}", err),
        _ => {}
    }
    match ssh_auth_by_pass() {
        Err(err) => println!("{:?}", err),
        _ => {}
    }
}
