/// Main application entry point
///
use eyre::{eyre, Result, WrapErr};
use clap::Parser;
mod args;
mod daemon;
mod netns;
use args::Args;
use netns::Netns;

fn main() -> Result<()> {
    let args = Args::parse();

    if args.name.is_empty() {
        return Err(eyre!("Missing --name argument"));
    }
    let netns = Netns::new(&args);

    if args.do_create {
        netns.do_create()
            .wrap_err("Failed to create network namespace")?;
        return Ok(())
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
