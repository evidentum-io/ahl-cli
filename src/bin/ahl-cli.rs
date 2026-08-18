//! The `ahl-cli` binary: argument parsing, the two output streams, and the exit code.
//!
//! Everything else lives in the library, so the whole command surface is testable without
//! spawning a process — see `ahl_cli::cli::run`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let outcome = ahl_cli::cli::run(std::env::args_os(), &mut stdout, &mut stderr);
    ExitCode::from(outcome.exit_code())
}
