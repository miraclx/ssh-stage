use std::io::{self, Read, Write};

use anyhow::{anyhow, bail, Context};

pub fn input(query: &str) -> io::Result<String> {
    print!("{}", query);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_owned())
}

struct State {
    session: ssh2::Session,
    agent: ssh2::Agent,
    username: String,
}

fn ssh_auth<F: Fn(&mut State) -> anyhow::Result<()>>(auther: F) -> anyhow::Result<State> {
    let addr = input("Enter the host address (e.g: localhost:22): ")?;
    let tcp = std::net::TcpStream::connect(addr)?;
    let mut session = ssh2::Session::new().context("failed to initialize an SSH session")?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .context("failed to connect to the SSH session")?;

    let mut agent = session.agent().context("sess.agent()")?;

    agent.connect().context("agent.connect()")?;

    let username = input("Enter a username to authorize: ")?;

    let mut state = State {
        session,
        agent,
        username,
    };

    auther(&mut state)?;

    if !state.session.authenticated() {
        bail!("authentication failure")
    }

    Ok(state)
}

fn ssh_auth_by_pk() -> anyhow::Result<State> {
    ssh_auth(|state| {
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

fn ssh_exec_auth_by_pass() -> anyhow::Result<State> {
    ssh_auth(|state| {
        let State {
            session, username, ..
        } = state;
        let password = input("Enter the password for this user: ")?;
        session.userauth_password(username, &password)?;

        Ok(())
    })
}

fn ssh_run_command(state: State) -> anyhow::Result<()> {
    let State { session, .. } = state;
    let mut channel = session.channel_session()?;

    channel.exec(CMD)?;

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

const CMD: &'static str = r#"{
    echo "\x1b[33mstderr: hello\x1b[0m" > /dev/stderr;
    echo "\x1b[34mstdout: world\x1b[0m" > /dev/stdout;
}"#;

fn main() {
    if cfg!(all(
        any(feature = "publickey", feature = "password"),
        not(all(feature = "publickey", feature = "password"))
    )) {
        if cfg!(feature = "publickey") {
            match ssh_auth_by_pk().and_then(ssh_run_command) {
                Err(err) => println!("{:?}", err),
                _ => {}
            };
        } else if cfg!(feature = "password") {
            match ssh_exec_auth_by_pass().and_then(ssh_run_command) {
                Err(err) => println!("{:?}", err),
                _ => {}
            }
        }

        return;
    }

    println!("please specify --features with either publickey or password");
    std::process::exit(1);
}
