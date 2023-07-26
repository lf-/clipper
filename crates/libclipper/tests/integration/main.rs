// SPDX-FileCopyrightText: 2023 Jade Lovelace
//
// SPDX-License-Identifier: MPL-2.0

//! For extremely annoying reasons, Clipper integration tests have to be quite
//! insane: since `wire_blahaj::unprivileged` forks, it must not be run from a
//! multithreaded process. In practice this means that we need to reexec as a
//! child process to actually run the test.
//!
//! Most inconveniently, Rust actually implemented this already and has not
//! stabilized it: <https://github.com/rust-lang/rust/issues/67650>
use std::{
    env,
    process::{Command, ExitCode, Stdio},
};

use libtest_mimic::{Arguments, Failed, Trial};

mod support;
mod tests;

const REEXEC_ENVVAR: &'static str = "__LIBCLIPPER_TEST_REEXEC";

fn self_reexec(name: &'static str, nocapture: bool) -> impl FnOnce() -> Result<(), Failed> {
    move || {
        let stdout = if nocapture {
            Stdio::inherit()
        } else {
            Stdio::piped()
        };
        let stderr = if nocapture {
            Stdio::inherit()
        } else {
            Stdio::piped()
        };

        let self_exe = env::current_exe()?;
        let out = Command::new(self_exe)
            .env(REEXEC_ENVVAR, name)
            .stdout(stdout)
            .stderr(stderr)
            .output()?;

        if !out.status.success() {
            let message = format!(
                "exit code: {}\nstdout:\n{}\nstderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );

            Err(message.into())
        } else {
            Ok(())
        }
    }
}

#[macro_export]
macro_rules! mktest {
    ($name:ident) => {
        inventory::submit! {
            crate::Test::new(
                concat!(module_path!(), "::", stringify!($name)),
                #[allow(unreachable_code)]
                || std::process::Termination::report($name()),
            )
        }
    };
}

struct Test {
    name: &'static str,
    func: fn() -> ExitCode,
}

impl Test {
    pub const fn new(name: &'static str, func: fn() -> ExitCode) -> Test {
        Test { name, func }
    }
}

inventory::collect!(Test);
fn main() -> ExitCode {
    let reexec_envvar = env::var(REEXEC_ENVVAR);

    if let Ok(test_name) = reexec_envvar {
        let test = inventory::iter::<Test>
            .into_iter()
            .find(|t| *t.name == test_name)
            .expect("wtf: reexec test name not found");

        return (test.func)();
    }

    let args = Arguments::from_args();

    let tests_reexec = inventory::iter::<Test>
        .into_iter()
        .map(|t| Trial::test(t.name, self_reexec(t.name, args.nocapture)))
        .collect::<Vec<_>>();

    libtest_mimic::run(&args, tests_reexec).exit();
}
