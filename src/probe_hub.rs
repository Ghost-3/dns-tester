//! Центр звезды (Хаб): координация граничных узлов и чистых ядер без хранения состояния сценария.

use crate::cli_node::CliNode;
use crate::cli_parse_core::{self, CliCommandSnap, CliIssue};
use crate::dns_core::{self, DnsParseSnap};
use crate::format_core;
use crate::primitives::{DnsWireQuery, Duration, Lang, ProbeMode, QueryId, TargetServer};
use crate::random_node::RandomNode;
use crate::tcp_node::{TcpIssue, TcpNode, TcpSnap};
use crate::udp_node::{UdpIssue, UdpNode, UdpSnap};
use crate::validation_core::{self, ValidationIssue, ValidationSnap};

pub enum AppSnap {
    Completed,
    Aborted(AppIssue),
}

pub enum AppIssue {
    Cli(CliIssue),
    Validation(ValidationIssue),
    Udp(UdpIssue),
    Tcp(TcpIssue),
    Both { udp: UdpIssue, tcp: TcpIssue },
}

enum UdpFlowSnap {
    Complete,
    Truncated,
    Failed(UdpIssue),
}

enum TcpFlowSnap {
    Complete,
    Failed(TcpIssue),
}

pub struct ProbeHub {
    pub cli: CliNode,
    pub random: RandomNode,
    pub udp: UdpNode,
    pub tcp: TcpNode,
}

impl ProbeHub {
    pub fn run(&self) -> AppSnap {
        let raw_args = self.cli.read_raw_args();
        self.run_with_args(&raw_args)
    }

    pub fn run_with_args(&self, raw_args: &[String]) -> AppSnap {
        let parsed = cli_parse_core::parse(raw_args);
        let lang = parsed.lang;

        let (mode, raw_ip, raw_domain, raw_timeout_ms) = match parsed.command {
            CliCommandSnap::Run {
                mode,
                raw_ip,
                raw_domain,
                raw_timeout_ms,
            } => (mode, raw_ip, raw_domain, raw_timeout_ms),
            CliCommandSnap::Aborted(issue) => {
                self.cli.print(&format_core::cli_issue(lang, &issue));
                return AppSnap::Aborted(AppIssue::Cli(issue));
            }
        };

        let (target, domain, timeout) = match validation_core::validate(
            &raw_ip,
            raw_domain.as_deref(),
            raw_timeout_ms.as_deref(),
        ) {
            ValidationSnap::Valid {
                target,
                domain,
                timeout,
            } => (target, domain, timeout),
            ValidationSnap::Invalid(issue) => {
                self.cli.print(&format_core::validation_issue(lang, &issue));
                return AppSnap::Aborted(AppIssue::Validation(issue));
            }
        };

        let query_id = self.random.next_query_id();
        let query = dns_core::encode_query(&domain, query_id);
        self.cli.print(&format_core::probe_banner(
            lang, target, &domain, mode, timeout, query_id,
        ));

        match mode {
            ProbeMode::ForceUdp => match self.run_udp(lang, target, timeout, query_id, &query) {
                UdpFlowSnap::Complete | UdpFlowSnap::Truncated => AppSnap::Completed,
                UdpFlowSnap::Failed(issue) => AppSnap::Aborted(AppIssue::Udp(issue)),
            },
            ProbeMode::ForceTcp => match self.run_tcp(lang, target, timeout, query_id, &query) {
                TcpFlowSnap::Complete => AppSnap::Completed,
                TcpFlowSnap::Failed(issue) => AppSnap::Aborted(AppIssue::Tcp(issue)),
            },
            ProbeMode::Both => {
                let udp_flow = self.run_udp(lang, target, timeout, query_id, &query);
                let tcp_flow = self.run_tcp(lang, target, timeout, query_id, &query);

                match (udp_flow, tcp_flow) {
                    (UdpFlowSnap::Failed(udp), TcpFlowSnap::Failed(tcp)) => {
                        AppSnap::Aborted(AppIssue::Both { udp, tcp })
                    }
                    (UdpFlowSnap::Failed(issue), TcpFlowSnap::Complete) => {
                        AppSnap::Aborted(AppIssue::Udp(issue))
                    }
                    (
                        UdpFlowSnap::Complete | UdpFlowSnap::Truncated,
                        TcpFlowSnap::Failed(issue),
                    ) => AppSnap::Aborted(AppIssue::Tcp(issue)),
                    (UdpFlowSnap::Complete | UdpFlowSnap::Truncated, TcpFlowSnap::Complete) => {
                        AppSnap::Completed
                    }
                }
            }
            ProbeMode::Auto => match self.run_udp(lang, target, timeout, query_id, &query) {
                UdpFlowSnap::Complete => AppSnap::Completed,
                UdpFlowSnap::Failed(issue) => AppSnap::Aborted(AppIssue::Udp(issue)),
                UdpFlowSnap::Truncated => {
                    self.cli.print(&format_core::tcp_fallback_notice(lang));
                    match self.run_tcp(lang, target, timeout, query_id, &query) {
                        TcpFlowSnap::Complete => AppSnap::Completed,
                        TcpFlowSnap::Failed(issue) => AppSnap::Aborted(AppIssue::Tcp(issue)),
                    }
                }
            },
        }
    }

    fn run_udp(
        &self,
        lang: Lang,
        target: TargetServer,
        timeout: Duration,
        query_id: QueryId,
        query: &DnsWireQuery,
    ) -> UdpFlowSnap {
        let (payload, rtt) = match self.udp.exchange(target, timeout, query) {
            UdpSnap::Received { payload, rtt } => (payload, rtt),
            UdpSnap::Failed(issue) => {
                self.cli.print(&format_core::udp_issue(lang, &issue));
                return UdpFlowSnap::Failed(issue);
            }
        };
        self.cli.print(&format_core::udp_received(lang, rtt));

        let parse_snap = dns_core::parse_response(&payload, query_id);
        self.cli.print(&format_core::dns_outcome(lang, &parse_snap));

        match parse_snap {
            DnsParseSnap::Truncated(_) => UdpFlowSnap::Truncated,
            DnsParseSnap::Complete(_) | DnsParseSnap::Malformed(_) => UdpFlowSnap::Complete,
        }
    }

    fn run_tcp(
        &self,
        lang: Lang,
        target: TargetServer,
        timeout: Duration,
        query_id: QueryId,
        query: &DnsWireQuery,
    ) -> TcpFlowSnap {
        let payload = match self.tcp.exchange(target, timeout, query) {
            TcpSnap::Received { payload, timings } => {
                self.cli.print(&format_core::tcp_received(lang, &timings));
                payload
            }
            TcpSnap::IncompletePayload {
                salvaged,
                expected_bytes,
                timings,
                reason,
            } => {
                self.cli.print(&format_core::tcp_incomplete(
                    lang,
                    &timings,
                    salvaged.len(),
                    expected_bytes,
                    &reason,
                ));
                salvaged
            }
            TcpSnap::Failed(issue) => {
                self.cli.print(&format_core::tcp_issue(lang, &issue));
                return TcpFlowSnap::Failed(issue);
            }
        };

        let parse_snap = dns_core::parse_response(&payload, query_id);
        self.cli.print(&format_core::dns_outcome(lang, &parse_snap));

        if matches!(parse_snap, DnsParseSnap::Truncated(_)) {
            self.cli.print(&format_core::tcp_truncated_anomaly(lang));
        }

        TcpFlowSnap::Complete
    }
}
