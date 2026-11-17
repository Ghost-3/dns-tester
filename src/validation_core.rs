//! Чистое расчётное ядро: доменная валидация адреса сервера, имени домена и таймаута.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use hickory_proto::rr::Name;

use crate::primitives::Duration;

const DEFAULT_DNS_PORT: u16 = 53;
const DEFAULT_DOMAIN: &str = "example.com.";
const DEFAULT_TIMEOUT_MS: u64 = 2_000;
const MAX_TIMEOUT_MS: u64 = 60_000;

/// Биографический примитив адреса DNS-сервера: рождается исключительно в `validation_core`.
#[derive(Clone, Copy)]
pub struct TargetServer(SocketAddr);

impl TargetServer {
    pub fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

/// Биографический примитив доменного имени (FQDN): рождается исключительно в `validation_core`.
#[derive(Clone)]
pub struct DomainName(Name);

impl DomainName {
    pub fn as_name(&self) -> &Name {
        &self.0
    }
}

pub enum ValidationSnap {
    Valid {
        target: TargetServer,
        domain: DomainName,
        timeout: Duration,
    },
    Invalid(ValidationIssue),
}

pub enum ValidationIssue {
    Target(TargetIssue),
    Domain(DomainIssue),
    Timeout(TimeoutIssue),
}

pub enum TargetIssue {
    Empty,
    ZeroPort,
    InvalidAddress(String),
}

pub enum DomainIssue {
    Empty,
    InvalidSyntax(String),
}

pub enum TimeoutIssue {
    NotANumber(String),
    Zero,
    TooLarge { provided_ms: u64, max_ms: u64 },
}

enum TargetStep {
    Valid(TargetServer),
    Invalid(TargetIssue),
}

enum DomainStep {
    Valid(DomainName),
    Invalid(DomainIssue),
}

enum TimeoutStep {
    Valid(Duration),
    Invalid(TimeoutIssue),
}

pub fn validate(
    raw_ip: &str,
    raw_domain: Option<&str>,
    raw_timeout_ms: Option<&str>,
) -> ValidationSnap {
    let target = match validate_target(raw_ip) {
        TargetStep::Valid(target) => target,
        TargetStep::Invalid(issue) => {
            return ValidationSnap::Invalid(ValidationIssue::Target(issue));
        }
    };

    let domain = match validate_domain(raw_domain) {
        DomainStep::Valid(domain) => domain,
        DomainStep::Invalid(issue) => {
            return ValidationSnap::Invalid(ValidationIssue::Domain(issue));
        }
    };

    let timeout = match validate_timeout(raw_timeout_ms) {
        TimeoutStep::Valid(timeout) => timeout,
        TimeoutStep::Invalid(issue) => {
            return ValidationSnap::Invalid(ValidationIssue::Timeout(issue));
        }
    };

    ValidationSnap::Valid {
        target,
        domain,
        timeout,
    }
}

fn validate_target(raw: &str) -> TargetStep {
    if raw.is_empty() {
        return TargetStep::Invalid(TargetIssue::Empty);
    }

    if let Ok(ip) = IpAddr::from_str(raw) {
        return TargetStep::Valid(TargetServer(SocketAddr::new(ip, DEFAULT_DNS_PORT)));
    }

    if let Ok(addr) = SocketAddr::from_str(raw) {
        if addr.port() == 0 {
            return TargetStep::Invalid(TargetIssue::ZeroPort);
        }
        return TargetStep::Valid(TargetServer(addr));
    }

    TargetStep::Invalid(TargetIssue::InvalidAddress(raw.to_string()))
}

fn validate_domain(raw: Option<&str>) -> DomainStep {
    let raw_str = raw.unwrap_or(DEFAULT_DOMAIN);
    if raw_str.trim().is_empty() {
        return DomainStep::Invalid(DomainIssue::Empty);
    }

    match Name::from_ascii(raw_str) {
        Ok(mut name) => {
            name.set_fqdn(true);
            DomainStep::Valid(DomainName(name))
        }
        Err(_) => DomainStep::Invalid(DomainIssue::InvalidSyntax(raw_str.to_string())),
    }
}

fn validate_timeout(raw: Option<&str>) -> TimeoutStep {
    let Some(raw_str) = raw else {
        return TimeoutStep::Valid(Duration::from_millis(DEFAULT_TIMEOUT_MS));
    };

    let Ok(ms) = raw_str.parse::<u64>() else {
        return TimeoutStep::Invalid(TimeoutIssue::NotANumber(raw_str.to_string()));
    };

    if ms == 0 {
        return TimeoutStep::Invalid(TimeoutIssue::Zero);
    }

    if ms > MAX_TIMEOUT_MS {
        return TimeoutStep::Invalid(TimeoutIssue::TooLarge {
            provided_ms: ms,
            max_ms: MAX_TIMEOUT_MS,
        });
    }

    TimeoutStep::Valid(Duration::from_millis(ms))
}
