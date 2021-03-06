use std::io::{self, Read, Write};
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, bail};

pub fn input(query: &str) -> io::Result<String> {
    print!("{}", query);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_owned())
}

struct State {
    session: ssh2::Session,
    username: String,
}

fn ssh_auth<F: Fn(&mut State) -> anyhow::Result<()>>(auther: F) -> anyhow::Result<State> {
    let addr = input("Enter the host address (e.g: localhost:22): ")?;
    let tcp = std::net::TcpStream::connect(addr)?;
    let mut session = ssh2::Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;

    let username = input("Enter a username to authorize: ")?;

    let mut state = State { session, username };

    auther(&mut state)?;

    if !state.session.authenticated() {
        bail!("authentication failure")
    }

    Ok(state)
}

fn ssh_auth_by_pk() -> anyhow::Result<State> {
    ssh_auth(|state| {
        let State { session, username } = state;
        let mut agent = session.agent()?;
        agent.connect()?;

        let publickey = input("Paste the public key for this user: ")?;

        agent.list_identities()?;

        let user_identity = sshkeys::PublicKey::from_string(&publickey)?.encode();
        let identity = agent
            .identities()?
            .into_iter()
            .find(|identity| user_identity == identity.blob())
            .ok_or_else(|| anyhow!("failed to match an authenticated identity"))?;

        agent.userauth(&username, &identity)?;

        Ok(())
    })
}

fn ssh_auth_by_pass() -> anyhow::Result<State> {
    ssh_auth(|state| {
        let State { session, username } = state;
        let password = input("Enter the password for this user: ")?;
        session.userauth_password(username, &password)?;

        Ok(())
    })
}

fn ssh_run(state: anyhow::Result<State>) -> anyhow::Result<()> {
    let State { session, .. } = state?;
    let mut channel = session.channel_session()?;

    channel.exec(CMD)?;

    let channel = Arc::new(RwLock::new(channel));

    println!("============================");

    let stdin_channel = channel.clone();
    let stdout_channel = channel.clone();
    let stderr_channel = channel.clone();

    let stdin_streamer = std::thread::spawn(move || -> anyhow::Result<()> {
        let channel = stdin_channel.read().unwrap();
        let mut stdin = io::stdin().lock();

        let mut buf = [0; 0x4000];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 {
                break;
            }

            channel.stream(0).write(&buf[..n])?;
        }

        Ok(())
    });

    let stdout_streamer = std::thread::spawn(move || -> anyhow::Result<()> {
        let channel = stdout_channel.read().unwrap();
        let mut stdout = io::stdout().lock();

        let mut buf = [0; 0x4000];
        while let Ok(n) = channel.stream(0).read(&mut buf) {
            if n == 0 {
                break;
            }

            stdout.write(&buf[..n])?;
        }

        Ok(())
    });

    let stderr_streamer = std::thread::spawn(move || -> anyhow::Result<()> {
        let channel = stderr_channel.read().unwrap();
        let mut stderr = io::stderr().lock();

        let mut buf = [0; 0x4000];
        while let Ok(n) = channel.stream(1).read(&mut buf) {
            if n == 0 {
                break;
            }

            stderr.write(&buf[..n])?;
        }

        Ok(())
    });

    stdin_streamer.join().unwrap()?;
    stdout_streamer.join().unwrap()?;
    stderr_streamer.join().unwrap()?;

    let mut channel = channel.write().unwrap();
    channel.wait_close()?;
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
        sleep 1
    done
}"#;

fn main() {
    if cfg!(all(
        any(feature = "publickey", feature = "password"),
        not(all(feature = "publickey", feature = "password"))
    )) {
        if cfg!(feature = "publickey") {
            match ssh_run(ssh_auth_by_pk()) {
                Err(err) => println!("{:?}", err),
                _ => {}
            };
        } else if cfg!(feature = "password") {
            match ssh_run(ssh_auth_by_pass()) {
                Err(err) => println!("{:?}", err),
                _ => {}
            }
        }

        return;
    }

    println!("please specify --features with *either* publickey or password");
    std::process::exit(1);
}
