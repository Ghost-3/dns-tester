// src/main.rs
//! Точка сборки: инициализация физических узлов, запуск центрального Хаба
//! и перевод итогового снимка в код завершения процесса ОС.

use std::process::ExitCode;

use dns_tester::cli_node::CliNode;
use dns_tester::cli_parse_core::CliIssue;
use dns_tester::probe_hub::{AppIssue, AppSnap, ProbeHub};
use dns_tester::random_node::RandomNode;
use dns_tester::tcp_node::TcpNode;
use dns_tester::udp_node::UdpNode;

const EXIT_CLI_ERROR: u8 = 2;
const EXIT_VALIDATION_ERROR: u8 = 3;
const EXIT_UDP_FAILED: u8 = 4;
const EXIT_TCP_FAILED: u8 = 5;
const EXIT_BOTH_FAILED: u8 = 6;

fn main() -> ExitCode {
    let hub = ProbeHub {
        cli: CliNode,
        random: RandomNode,
        udp: UdpNode,
        tcp: TcpNode,
    };

    map_exit_code(&hub.run())
}

fn map_exit_code(snap: &AppSnap) -> ExitCode {
    match snap {
        AppSnap::Completed | AppSnap::Aborted(AppIssue::Cli(CliIssue::HelpRequested)) => {
            ExitCode::SUCCESS
        }
        AppSnap::Aborted(AppIssue::Cli(
            CliIssue::MissingArguments
            | CliIssue::UnknownFlag(_)
            | CliIssue::ConflictingModes
            | CliIssue::ConflictingLangs
            | CliIssue::TooManyArguments(_),
        )) => ExitCode::from(EXIT_CLI_ERROR),
        AppSnap::Aborted(AppIssue::Validation(_)) => ExitCode::from(EXIT_VALIDATION_ERROR),
        AppSnap::Aborted(AppIssue::Udp(_)) => ExitCode::from(EXIT_UDP_FAILED),
        AppSnap::Aborted(AppIssue::Tcp(_)) => ExitCode::from(EXIT_TCP_FAILED),
        AppSnap::Aborted(AppIssue::Both { .. }) => ExitCode::from(EXIT_BOTH_FAILED),
    }
}
