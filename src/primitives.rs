//! Алфавит системы: пассивные структуры данных и реэкспорт биографических примитивов.

use std::net::{Ipv4Addr, Ipv6Addr};
pub use std::time::Duration;

pub use crate::dns_core::DnsWireQuery;
pub use crate::random_node::QueryId;
pub use crate::validation_core::{DomainName, TargetServer};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ru,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    Auto,
    ForceUdp,
    ForceTcp,
    Both,
}

/// Три последовательные непересекающиеся фазы TCP-обмена.
/// Полное время обмена равно сумме всех трёх фаз.
#[derive(Clone, Copy)]
pub struct TcpTimings {
    pub connect: Duration,
    pub first_byte: Duration,
    pub transfer: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Unknown(u16),
}

pub enum DnsRecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Unknown { record_type: u16 },
}

pub struct DnsRecord {
    pub name: String,
    pub ttl: u32,
    pub data: DnsRecordData,
}

pub struct DnsPacket {
    pub rcode: DnsRcode,
    pub recursion_available: bool,
    pub records: Box<[DnsRecord]>,
}
