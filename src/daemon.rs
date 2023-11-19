/// Network namespace daemon
///
/// The daemon is started at the same time than the network namespace.
/// Its responsability is to destroy the network namespace when no one is using it anymore.
///
/// For this purpose, we use ipc connection to determine the number of clients using the network
/// namespace.
///
/// The design allows to catch even when a client is forcely terminated (SIGKILL).
///
use eyre::{Result, WrapErr};
use std::os::unix::net::{UnixListener, UnixStream};
use std::io::Read;
use crate::Netns;

fn handle_client(stream: &mut UnixStream) {
    let mut buff = [0; 32];
    loop {
        match stream.read(&mut buff) {
            Ok(ret) => {
                if ret <= 0 {
                    println!("Connection to daemon closed");
                    return;
                }
            },
            Err(e) => {
                println!("Connection to daemon error: {}", e);
                return;
            },
        }
    }
}

pub fn spawn(netns: &Netns) -> Result<()> {
    let mut refcount = 0;
    let (tx, rx) = std::sync::mpsc::channel();
    let listener = UnixListener::bind(netns.ipc_path())
        .wrap_err("bind ipc socket failed")?;

    println!("Starting network namespace daemon");
    let daemon = daemonize::Daemonize::new();
    daemon.start()
        .wrap_err("Failed to start deamon")?;

    // Count the number of ipc socket opened
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let tx = tx.clone();
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(_) => {continue;},
            };
            std::thread::spawn(move || {
                tx.send(1).unwrap();
                handle_client(&mut stream);
                tx.send(-1).unwrap();
            });
        }
    });

    // Close the network namespace when the number of ipc socket
    // opened reaches 0.
    loop {
        let increment = rx.recv().unwrap();
        refcount += increment;
        if refcount <= 0 {
            break;
        }
    }

    netns.destroy();

    Ok(())
}

