//! Unprivileged capture on Linux.
//!
//! This is achieved by yeeting the target process into a namespace using e.g.
//! rootlesskit + slirp4netns, and then taking a handle to the TAP device
//! inside the net namespace and executing the capture in the host namespace.
//!
//!
//! Inspired by: <https://github.com/rootless-containers/slirp4netns/blob/master/main.c#L223>
//! and <https://github.com/giuseppe/become-root/blob/master/main.c>

use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::Error as IoError,
    io::{IoSlice, IoSliceMut, Read, Write},
    mem,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    process::{exit, Command, Stdio},
};

use nix::{
    cmsg_space,
    errno::Errno,
    ioctl_readwrite_bad, libc,
    sched::{unshare, CloneFlags},
    sys::socket::{
        bind, recvmsg, sendmsg, socket, socketpair, AddressFamily, ControlMessage, LinkAddr,
        MsgFlags, SockFlag, SockProtocol, SockType, SockaddrLike, UnixAddr,
    },
    unistd::{close, execvp, fork, pipe, ForkResult, Pid},
};

const DEV_NAME: &'static str = "tap0";

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}: {1}")]
    Errno(&'static str, Errno),
    #[error("{0}: {1}")]
    IoError(&'static str, std::io::Error),
    #[error("{0}")]
    StringError(&'static str),
    #[error("{0}")]
    Other(DynError),
}

trait AddContext<T> {
    fn context(self, s: &'static str) -> Result<T, Error>;
}

impl<T> AddContext<T> for Result<T, Errno> {
    fn context(self, s: &'static str) -> Result<T, Error> {
        self.map_err(|e| Error::Errno(s, e))
    }
}

impl<T> AddContext<T> for Result<T, std::io::Error> {
    fn context(self, s: &'static str) -> Result<T, Error> {
        self.map_err(|e| Error::IoError(s, e))
    }
}

fn err(s: &'static str) -> Error {
    Error::StringError(s)
}

ioctl_readwrite_bad!(get_if_index, libc::SIOCGIFINDEX, libc::ifreq);

pub fn make_capture_socket(dev_name: &str) -> Result<RawFd, Error> {
    let capture_sock = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::Raw,
    )
    .context("make_capture_socket socket()")?;

    // horrible code, but it's equivalent to the way to do it in C
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let ifr_name_len = mem::size_of_val(&ifr.ifr_name);

    assert_eq!(mem::size_of::<libc::c_char>(), mem::size_of::<u8>());
    ifr.ifr_name[..ifr_name_len.min(dev_name.as_bytes().len())]
        .copy_from_slice(unsafe { &*(dev_name.as_bytes() as *const _ as *const [libc::c_char]) });

    unsafe { get_if_index(capture_sock, &mut ifr).context("get interface index")? };

    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = unsafe { ifr.ifr_ifru.ifru_ifindex };

    let sll = unsafe {
        LinkAddr::from_raw(
            &sll as *const _ as *const libc::sockaddr,
            Some(mem::size_of::<libc::sockaddr_ll>() as u32),
        )
        .unwrap()
    };

    bind(capture_sock, &sll).context("bind capture socket")?;

    Ok(capture_sock)
}

/// Attaches to the network and user namespaces of the target process and
/// sends the capture fd back out via a Unix socket.
pub unsafe fn send_capture_socket_for_ns(
    pid: u64,
    dev_name: &str,
    sock_fdnum: RawFd,
) -> Result<(), DynError> {
    let userns = format!("/proc/{pid}/ns/user");
    let netns = format!("/proc/{pid}/ns/net");

    let mut rdonly = OpenOptions::new();
    rdonly.read(true);

    let userns = rdonly.open(userns)?;
    let netns = rdonly.open(netns)?;

    nix::sched::setns(userns.as_raw_fd(), CloneFlags::CLONE_NEWUSER)?;
    nix::sched::setns(netns.as_raw_fd(), CloneFlags::CLONE_NEWNET)?;

    let capture_sock = make_capture_socket(&dev_name)?;

    eprintln!("capture sock: {capture_sock}");

    sendmsg::<UnixAddr>(
        sock_fdnum,
        &[IoSlice::new(&[b'\0'])],
        &[ControlMessage::ScmRights(&[capture_sock])],
        MsgFlags::empty(),
        None,
    )?;

    Ok(())
}

fn wait_for_1_and_close(fd: RawFd) -> Result<(), Error> {
    // I could deal with EINTR myself but I could also make std do it :^)
    let mut fd = unsafe { File::from_raw_fd(fd) };
    let mut buf = [0u8; 1];
    fd.read_exact(&mut buf).context("wait for pipe")?;
    if &buf != &[b'1'] {
        tracing::error!("wait_for_1: did not get 1, got: {buf:?}");
        return Err(Error::Other("wait_for_1 did not get 1".into()));
    }

    Ok(())
}

fn send_1_and_close(fd: RawFd) -> Result<(), IoError> {
    unsafe { File::from_raw_fd(fd).write(&[b'1'])? };
    Ok(())
}

fn parent(
    child_pid: Pid,
    sock: RawFd,
    notify_child_ready_pipe: RawFd,
    notify_net_ready_pipe: RawFd,
    notify_close_pipe: RawFd,
    callback: impl FnOnce(RawFd),
) -> Result<(), Error> {
    tracing::debug!("parent notified, starting networking");
    wait_for_1_and_close(notify_child_ready_pipe)?;

    let mut networking = Command::new("slirp4netns")
        .arg("-c")
        .arg("-r")
        .arg(notify_net_ready_pipe.to_string())
        .arg("-e")
        .arg(notify_close_pipe.to_string())
        .arg(child_pid.to_string())
        .arg(DEV_NAME)
        .stdin(Stdio::null())
        // FIXME: debug output for slirp4netns going into tracing
        // Unsure how to implement: really I probably should just tokio::spawn
        // something though.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn slirp4netns")?;

    close(notify_net_ready_pipe).context("close notify_net_ready_pipe")?;
    close(notify_close_pipe).context("close notify_close_pipe")?;

    let mut buf = [0u8; 1];
    let mut bufs = [IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = cmsg_space!(RawFd);
    let recvd = recvmsg::<UnixAddr>(sock, &mut bufs, Some(&mut cmsg_buf), MsgFlags::empty())
        .context("recvmsg")?;
    close(sock).context("close fd passing socket")?;

    let rights = recvd.cmsgs().next().ok_or(err("no cmsgs"))?;
    let fd = match rights {
        nix::sys::socket::ControlMessageOwned::ScmRights(fds) => Ok(fds[0]),
        _ => Err(err("wrong cmsg type")),
    }?;

    tracing::debug!("got capture fd: {fd}");
    callback(fd);

    networking.wait().context("wait for slirp4netns")?;

    Ok(())
}

fn child(
    args: Vec<String>,
    sock: RawFd,
    notify_child_ready_pipe: RawFd,
    notify_net_ready_pipe: RawFd,
) -> Result<(), Error> {
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).context("unshare")?;
    send_1_and_close(notify_child_ready_pipe).context("notify parent that child is ready")?;
    tracing::debug!("child notify");

    tracing::debug!("net ready pipe: {notify_net_ready_pipe}");

    wait_for_1_and_close(notify_net_ready_pipe)?;
    tracing::debug!("child knows network is ready, lets go");

    let capture_sock = make_capture_socket(DEV_NAME)?;

    sendmsg::<UnixAddr>(
        sock,
        &[IoSlice::new(&[b'\0'])],
        &[ControlMessage::ScmRights(&[capture_sock])],
        MsgFlags::empty(),
        None,
    )
    .context("sendmsg capture socket")?;
    close(sock).context("close fd passing socket")?;
    close(capture_sock).context("close capture socket")?;

    let args: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    let exe = &args[0];
    execvp(exe, &args).context("execve child in sandbox")?;

    Ok(())
}

/// Runs the given command in a user plus network namespace, with slirp4netns
/// providing NAT.
///
/// The provided callback will be invoked in the parent process when the child
/// is started, with a fd for the raw capture socket.
///
/// Safety: cannot be run from a (currently) multithreaded process.
pub unsafe fn run_in_ns(args: Vec<String>, callback: impl FnOnce(RawFd)) -> Result<(), DynError> {
    // ceci n'est pas une pipe
    let (parent_sock, child_sock) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )?;

    // ceci, par contre, est une pipe
    // (read, write)
    let notify_child_ready_pipe = pipe()?;
    let notify_net_ready_pipe = pipe()?;
    let notify_close_pipe = pipe()?;

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            close(child_sock)?;
            close(notify_child_ready_pipe.1)?;
            close(notify_net_ready_pipe.0)?;
            close(notify_close_pipe.1)?;

            let span = tracing::span!(tracing::Level::DEBUG, "parent");
            let _guard = span.enter();

            tracing::debug!("parent! child pid = {child}");
            parent(
                child,
                parent_sock,
                notify_child_ready_pipe.0,
                notify_net_ready_pipe.1,
                notify_close_pipe.0,
                callback,
            )?;
        }
        ForkResult::Child => {
            close(parent_sock)?;
            close(notify_child_ready_pipe.0)?;
            close(notify_net_ready_pipe.1)?;
            close(notify_close_pipe.0)?;

            // notify_close_pipe.1 is notably leaked in the child: this causes
            // slirp4netns to terminate along with the child process
            //
            // XXX: this is kinda evil, and we should probably use waitpid with
            // tokio somehow and pass it off to the host, but whatever.

            let span = tracing::span!(tracing::Level::DEBUG, "child");
            let _guard = span.enter();

            tracing::debug!("child!");
            match child(
                args,
                child_sock,
                notify_child_ready_pipe.1,
                notify_net_ready_pipe.0,
            ) {
                Ok(_) => {}
                Err(e) => println!("Error in child: {e}"),
            }
            exit(0);
        }
    }
    Ok(())
}
