use std::os::raw::c_int;

use wire_blahaj::unprivileged::{send_capture_socket_for_ns, Error};

fn main() -> Result<(), Error> {
    let mut args = std::env::args();
    let argv0 = args.next().unwrap();
    if args.len() != 3 {
        eprintln!("usage: {argv0:?} PID DEV_NAME UNIX_SOCK_FD");
        return Ok(());
    }

    let pid = args.next().unwrap().parse::<u64>()?;
    let dev_name = args.next().unwrap();
    let sock_fdnum = args.next().unwrap().parse::<c_int>()?;

    unsafe { send_capture_socket_for_ns(pid, &dev_name, sock_fdnum)? };

    Ok(())
}
