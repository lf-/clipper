<!--
SPDX-FileCopyrightText: 2023 Jade Lovelace

SPDX-License-Identifier: MPL-2.0
-->

# (Complaints about) Cargo and libtest

TL;DR they have extensibility issues and mark stuff nightly.

- Workspaces conflate what you want to build with what you want to work on
  simultaneously. For example, you don't care about fixture bins in production
  builds.

  Further, there's one lockfile per workspace.
- We want to run tests in a separate execve() for fairly reasonable reasons of
  our fork crimes making it UB to run from a multithreaded program. Fixed by
  building a reexec thing with libtest_mimic.

  It might be easier to eliminate the mallocs, but it feels dirty since they
  could be readded as implementation details of std or whatever.
- We have to use the nightly bindeps feature, which has bad UX since you have
  to pass `-Z bindeps` to cargo commands.

  https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#artifact-dependencies
