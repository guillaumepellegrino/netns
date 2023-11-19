/// Main application entry point
///
use eyre::{eyre, Result, WrapErr};
use clap::Parser;
mod args;
mod daemon;
mod netns;
use args::Args;
use netns::Netns;
use std::process::Command;

fn restart_with_sudo() -> Result<()> {
    let me = std::fs::read_link("/proc/self/exe")?;

    let mut cmd = Command::new("sudo");
    cmd.arg("-E").arg(me);

    for arg in std::env::args().skip(1) {
        cmd.arg(arg);
    }

    cmd.status()?;

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.name.is_empty() {
        return Err(eyre!("Missing --name argument"));
    }

    if nix::unistd::geteuid() != nix::unistd::ROOT {
        println!("netns must be started as root");
        return restart_with_sudo();
    }

    let netns = Netns::new(&args);

    if args.do_create {
        netns.do_create()
            .wrap_err("Failed to create network namespace")?;
        return Ok(());
    }
    if args.do_join {
        netns.do_join()
            .wrap_err("Failed to join network namespace")?;

        netns.run()
            .wrap_err("Failed to run command in network namespace")?;

        return Ok(())
    }
    if args.do_daemon {
        daemon::spawn(&netns)
            .wrap_err("Failed to start network namespace daemon")?;
        return Ok(())
    }
    if args.destroy {
        netns.destroy();
        return Ok(())
    }

    if let Err(_) = netns.join() {
        if netns.exists() {
            println!("network namespace was not properly cleanup: Destroy it");
            netns.destroy();
        }
        netns.create()
            .wrap_err("Failed to create network namespace")?;
        netns.join()
            .wrap_err("Failed to join network namespace")?;
    }

    Ok(())
}
