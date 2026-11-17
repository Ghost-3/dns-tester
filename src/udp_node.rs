//! Граничный узел сети: обмен DNS-пакетами поверх UDP с разделением фаз подготовки и сети.

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Instant;

use crate::primitives::{DnsWireQuery, Duration, TargetServer};

/// Буфер на стеке (4 КБ покрывает стандартный DNS 512 байт и EDNS0).
const UDP_BUFFER_SIZE: usize = 4096;

pub enum UdpSnap {
    Received { payload: Box<[u8]>, rtt: Duration },
    Failed(UdpIssue),
}

pub enum UdpIssue {
    /// Сбой при открытии/настройке локального сокета или проверке маршрута (до отправки пакета).
    SetupFailed { reason: UdpIoIssue },
    /// Сбой во время сетевого обмена (после старта таймера).
    ExchangeFailed {
        elapsed: Duration,
        reason: UdpIoIssue,
    },
}

pub enum UdpIoIssue {
    TimedOut,
    ConnectionRefused,
    NetworkUnreachable,
    Unknown(io::Error),
}

enum SocketStep {
    Ready(UdpSocket),
    Failed(UdpIoIssue),
}

pub struct UdpNode;

impl UdpNode {
    pub fn exchange(
        &self,
        target: TargetServer,
        timeout: Duration,
        query: &DnsWireQuery,
    ) -> UdpSnap {
        let socket = match prepare_socket(target, timeout) {
            SocketStep::Ready(s) => s,
            SocketStep::Failed(reason) => {
                return UdpSnap::Failed(UdpIssue::SetupFailed { reason });
            }
        };

        let mut buf = [0u8; UDP_BUFFER_SIZE];
        let start = Instant::now();

        if let Err(e) = socket.send(query.as_bytes()) {
            return UdpSnap::Failed(UdpIssue::ExchangeFailed {
                elapsed: start.elapsed(),
                reason: classify_io_error(e),
            });
        }

        let received_len = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(e) => {
                return UdpSnap::Failed(UdpIssue::ExchangeFailed {
                    elapsed: start.elapsed(),
                    reason: classify_io_error(e),
                });
            }
        };

        let rtt = start.elapsed();

        UdpSnap::Received {
            payload: Box::from(&buf[..received_len]),
            rtt,
        }
    }
}

fn prepare_socket(target: TargetServer, timeout: Duration) -> SocketStep {
    let remote_addr = target.socket_addr();
    let bind_addr = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => return SocketStep::Failed(classify_io_error(e)),
    };
    if let Err(e) = socket.connect(remote_addr) {
        return SocketStep::Failed(classify_io_error(e));
    }
    if let Err(e) = socket.set_write_timeout(Some(timeout)) {
        return SocketStep::Failed(classify_io_error(e));
    }
    if let Err(e) = socket.set_read_timeout(Some(timeout)) {
        return SocketStep::Failed(classify_io_error(e));
    }

    SocketStep::Ready(socket)
}

fn classify_io_error(err: io::Error) -> UdpIoIssue {
    match err.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => UdpIoIssue::TimedOut,
        // На Windows ICMP Port Unreachable в UDP возвращается как ConnectionReset (WSAECONNRESET)
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => UdpIoIssue::ConnectionRefused,
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => {
            UdpIoIssue::NetworkUnreachable
        }
        _ => UdpIoIssue::Unknown(err),
    }
}
