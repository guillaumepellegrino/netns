use clap::Parser;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::ffi::CString;
use std::os::linux::fs::MetadataExt;
use std::process::Command;
use std::io::{Read, Write, Seek};
use eyre::{eyre, Result, WrapErr};

static NETNS_DIR: &str = "/tmp/netns";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the network namespace
    #[arg(short, long)]
    name: String,

    /// Interface name to enslave in the network namespace
    #[arg(short, long)]
    ifname: Vec<String>,

    /// Destroy the network namespace
    #[arg(short, long)]
    destroy: bool,

    /// Do the real work to create the network namespace
    #[arg(long, hide=true)]
    do_create: bool,

    /// Do the real work to join the network namespace
    #[arg(long, hide=true)]
    do_join: bool,
}

struct Netns {
    name: String,
    interfaces: Vec<String>,
    dirpath: String,
    netnspath: String,
    utsnspath: String,
    mntnspath: String,
    refcountpath: String,
    current_dir: PathBuf,
}

fn mount_bind<P1: ?Sized + nix::NixPath, P2: ?Sized + nix::NixPath>(source: &P1, target: &P2) -> nix::Result<()> {
    nix::mount::mount(Some(source), target, None::<&str>, nix::mount::MsFlags::MS_BIND, None::<&str>)
}

fn kill_by_inode(entry: std::fs::DirEntry, netns_inode: u64) -> Result<()> {
    let name = entry.file_name();
    let name = match name.to_str() {
        Some(name) => name,
        None => {return Ok(());},
    };
    let pid = match name.parse::<i32>() {
        Ok(pid) => pid,
        Err(_) => {return Ok(());},
    };
    let entry_netns = entry.path().join("ns/net");
    let entry_metadata = match std::fs::metadata(&entry_netns) {
        Ok(meta) => meta,
        Err(_) => {return Ok(());},
    };
    let entry_inode = entry_metadata.st_ino();
    if entry_inode != netns_inode {
        return Ok(());
    }
    println!("Kill {}", pid);
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGKILL)?;
    Ok(())
}

impl Netns {
    pub fn new(args: &Args) -> Self {
        Self {
            name: args.name.clone(),
            interfaces: args.ifname.clone(),
            dirpath: format!("{}/{}", NETNS_DIR, &args.name),
            netnspath: format!("{}/{}/net", NETNS_DIR, &args.name),
            utsnspath: format!("{}/{}/uts", NETNS_DIR, &args.name),
            mntnspath: format!("{}/{}/mnt", NETNS_DIR, &args.name),
            refcountpath: format!("{}/{}/refcount", NETNS_DIR, &args.name),
            current_dir: std::env::current_dir().unwrap(),
        }
    }

    pub fn exists(&self) -> bool {
        Path::new(&self.netnspath).is_file()
    }

    fn killall_by_inode(&self) -> Result<()> {
        let self_metadata = std::fs::metadata("/proc/self/ns/net")?;
        let self_inode = self_metadata.st_ino();
        let netns_metadata = std::fs::metadata(&self.netnspath)?;
        let netns_inode = netns_metadata.st_ino();
        println!("NETNS Inode: {}", netns_inode);

        // sanity check
        if self_inode == netns_inode {
            return Err(eyre!("Destroy command must be called outside the container"));
        }

        for entry in std::fs::read_dir("/proc").expect("/proc is not mounted") {
            if let Ok(entry) = entry {
                if let Err(e) = kill_by_inode(entry, netns_inode) {
                    println!("Failed to kill process: {}", e);
                }
            }
        }

        Ok(())
    }

    pub fn do_create(&self) -> Result<()> {
        nix::sched::unshare(
            nix::sched::CloneFlags::CLONE_NEWNET |
            nix::sched::CloneFlags::CLONE_NEWUTS |
            nix::sched::CloneFlags::CLONE_NEWNS)?;
        nix::unistd::sethostname(&self.name)?;

        let flags = nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE;
        nix::mount::mount(None::<&str>, "/", None::<&str>, flags, None::<&str>)?;

        // Let's notify the parent process than we are done.
        println!("DO_CREATE_DONE");

        // Wait until the parent process wake us to exit
        nix::unistd::pause();

        Ok(())
    }

    pub fn create(&self) -> Result<()> {
        let mut buf = [0; 32];

        println!("Creating network namespace {}", self.name);

        std::fs::create_dir_all(&self.dirpath)?;
        std::fs::File::create(&self.netnspath)?;
        std::fs::File::create(&self.utsnspath)?;
        std::fs::File::create(&self.mntnspath)?;
        std::fs::File::create(&self.refcountpath)?;

        nix::mount::mount(Some(self.dirpath.as_str()), self.dirpath.as_str(), None::<&str>,
            nix::mount::MsFlags::MS_BIND, None::<&str>)?;

        nix::mount::mount(None::<&str>, self.dirpath.as_str(), None::<&str>,
            nix::mount::MsFlags::MS_PRIVATE, None::<&str>)?;

        // Let's run create the network container in a child process
        let mut child = Command::new("/proc/self/exe")
            .arg("--name").arg(&self.name)
            .arg("--do-create")
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        // Wait until network container is created
        let mut stdout = child.stdout.take().unwrap();
        stdout.read(&mut buf)?;
        let msg = std::str::from_utf8(&buf)?;
        if !msg.starts_with("DO_CREATE_DONE") {
            return Err(eyre!("Unexpected msg from child process: {:?}", msg));
        }

        // mount bind network container on /tmp/nents/{name}/XXX
        let pid = child.id();
        mount_bind(format!("/proc/{}/ns/net", pid).as_str(), self.netnspath.as_str())?;
        mount_bind(format!("/proc/{}/ns/uts", pid).as_str(), self.utsnspath.as_str())?;
        mount_bind(format!("/proc/{}/ns/mnt", pid).as_str(), self.mntnspath.as_str())?;


        for ifname in &self.interfaces {
            Self::interface_setnetns(ifname, pid)
                .wrap_err(format!("Failed to set interface {} in netns", ifname))?;
        }

        child.kill()?;

        Ok(())
    }

    pub fn destroy(&self) -> Result<()> {
        if !self.exists() {
            println!("Network namespace {} is already destroyed", self.name);
            return Ok(())
        }
        println!("Destroying network namespace {}", self.name);

        // Stop running processes
        self.killall_by_inode()?;

        // Umount namespaces files
        for path in [&self.netnspath, &self.utsnspath, &self.mntnspath] {
            if let Err(e) = nix::mount::umount(path.as_str()) {
                println!("Error umount({}): {:?}", path, e);
            }
        }

        if let Err(e) = nix::mount::umount(self.dirpath.as_str()) {
            println!("Error umount({}): {:?}", self.dirpath, e);
        }

        // Remove namespace directory
        if let Err(e) = std::fs::remove_dir_all(&self.dirpath) {
            println!("Error: {:?}", e);
        }

        Ok(())
    }

    pub fn do_join(&self) -> Result<()> {
        println!("Joining network namespace {}", self.name);
        let netns = File::open(&self.netnspath)?;
        let utsns = File::open(&self.utsnspath)?;
        let mntns = File::open(&self.mntnspath)?;

        nix::sched::setns(netns.as_fd(), nix::sched::CloneFlags::CLONE_NEWNET)?;
        nix::sched::setns(utsns.as_fd(), nix::sched::CloneFlags::CLONE_NEWUTS)?;
        nix::sched::setns(mntns.as_fd(), nix::sched::CloneFlags::CLONE_NEWNS)?;

        Ok(())
    }

    pub fn join(&self) {
        if let Err(e) = Command::new("/proc/self/exe")
            .arg("--name").arg(&self.name)
            .arg("--do-join")
            .status() {
            println!("Failed to join network namespace: {}", e);
        }
    }

    fn interface_setnetns(ifname: &str, netnspid: u32) -> Result<()> {
        let netns = format!("{}", netnspid);
        Command::new("ip")
            .arg("link").arg("set").arg(ifname).arg("netns").arg(netns)
            .status()?;
        Ok(())
    }

    pub fn run(&self) -> Result<()> {
        let shell = std::env::var("SHELL").unwrap_or("bash".to_string());
        if let Ok(username) = std::env::var("SUDO_USER") {
            let user = nix::unistd::User::from_name(&username).unwrap().unwrap();
            std::env::set_var("USER", &user.name);
            std::env::set_var("USERNAME", &user.name);
            std::env::set_var("LOGNAME", &user.name);
            std::env::set_var("HOME", &user.dir);

            let groups = nix::unistd::getgrouplist(&CString::new(user.name).unwrap(), user.gid)?;
            nix::unistd::setgroups(&groups)?;
            nix::unistd::setgid(user.gid)?;
            nix::unistd::setegid(user.gid)?;
            nix::unistd::setuid(user.uid)?;
            nix::unistd::seteuid(user.uid)?;
        }

        std::env::set_current_dir(&self.current_dir)?;

        Command::new(&shell)
            .status()?;
        Ok(())
    }

    fn refcount_inspect<F: FnMut(i32)->i32>(&self, mut inspect: F) -> Result<i32> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.refcountpath)
            .wrap_err("open failed")?;
        let fd = file.as_raw_fd();
        nix::fcntl::flock(fd, nix::fcntl::FlockArg::LockExclusive).wrap_err("flock failed")?;
        let mut string = String::new();
        file.read_to_string(&mut string).wrap_err("read failed")?;
        let refcount = string.parse::<i32>().unwrap_or(0);
        let new_refcount = inspect(refcount);

        if new_refcount != refcount {
            file.set_len(0).wrap_err("truncate failed")?;
            file.rewind().wrap_err("rewind failed")?;
            file.write_fmt(format_args!("{}", new_refcount)).wrap_err("write failed")?;
        }
        Ok(new_refcount)
    }

    pub fn refcount_increment(&self) -> Result<i32> {
        self.refcount_inspect(|refcount| refcount + 1)
    }

    pub fn refcount_decrement(&self) -> Result<i32> {
        self.refcount_inspect(|refcount| refcount - 1)
    }
}

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
    if args.destroy {
        netns.destroy()
            .wrap_err("Failed to destroy network namespace")?;
        return Ok(())
    }

    if !netns.exists() {
        netns.create()
            .wrap_err("Failed to create network namespace")?;
    }

    if let Err(e) = netns.refcount_increment() {
        println!("Failed to increment refcount: {}", e);
    }
    netns.join();
    let refcount = match netns.refcount_decrement() {
        Ok(refcount) => refcount,
        Err(e) => {
            println!("Failed to decrement refcount: {}", e);
            println!("Assuming refcount = 0");
            0
        }
    };
    println!("netns reference count: {}", refcount);
    if refcount <= 0 {
        netns.destroy()
            .wrap_err("Failed to destroy network namespace")?;
    }

    Ok(())
}
