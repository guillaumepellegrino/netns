/// Network Namespace command line arguments
///
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Name of the network namespace
    #[arg(short, long)]
    pub name: String,

    /// Interface name to enslave in the network namespace
    #[arg(short, long)]
    pub ifname: Vec<String>,

    /// Destroy the network namespace
    #[arg(short, long)]
    pub destroy: bool,

    /// Do the real work to create the network namespace
    #[arg(long, hide=true)]
    pub do_create: bool,

    /// Do the real work to join the network namespace
    #[arg(long, hide=true)]
    pub do_join: bool,

    /// Do the real work to start the network namespace daemon
    #[arg(long, hide=true)]
    pub do_daemon: bool,
}

