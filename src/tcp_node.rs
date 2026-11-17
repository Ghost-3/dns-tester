//! Граничный узел сети: обмен DNS-пакетами поверх TCP с 2-байтовым префиксом длины (RFC 1035),
//! замером трёх непересекающихся фаз и спасением частично полученных пакетов.

use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

use crate::primitives::{DnsWireQuery, Duration, TargetServer, TcpTimings};

pub enum TcpSnap {
    Received {
        payload: Box<[u8]>,
        timings: TcpTimings,
    },
    /// Поток оборвался после получения хотя бы 1 байта тела DNS-пакета;
    /// полученные байты сохраняются для передачи в парсер `dns_core`.
    IncompletePayload {
        salvaged: Box<[u8]>,
        expected_bytes: usize,
        timings: TcpTimings,
        reason: TcpIoIssue,
    },
    Failed(TcpIssue),
}

pub enum TcpIssue {
    /// Фаза 1: Сбой при установке или настройке соединения.
    Connect {
        elapsed: Duration,
        reason: TcpIoIssue,
    },
    /// Фаза 2: Соединение установлено, но сбой произошёл при отправке или ожидании 1-го байта.
    FirstByte {
        connect: Duration,
        elapsed: Duration,
        reason: TcpIoIssue,
    },
    /// Фаза 3: Первый байт получен, но дочитать заголовок длины или получить хотя бы 1 байт тела не удалось.
    Transfer {
        timings: TcpTimings,
        reason: TransferIssue,
    },
}

pub enum TransferIssue {
    /// Пришёл только 1 из 2 байтов заголовка длины пакета.
    IncompleteLengthHeader(TcpIoIssue),
    /// Сервер прислал заголовок длины 0x0000 (0 байт).
    ZeroLengthHeader,
    /// Заголовок длины прочитан (> 0), но поток оборвался на 0 байтах тела пакета.
    EmptyPayload {
        expected_bytes: usize,
        reason: TcpIoIssue,
    },
}

pub enum TcpIoIssue {
    TimedOut,
    ConnectionRefused,
    ConnectionReset,
    NetworkUnreachable,
    UnexpectedEof,
    Unknown(io::Error),
}

enum ConnectStep {
    Ready {
        stream: TcpStream,
        connect_time: Duration,
    },
    Failed {
        elapsed: Duration,
        reason: TcpIoIssue,
    },
}

enum FirstByteStep {
    Received {
        len_buf: [u8; 2],
        first_chunk_len: usize,
        first_byte_time: Duration,
    },
    Failed {
        elapsed: Duration,
        reason: TcpIoIssue,
    },
}

enum ReadStep {
    Bytes(usize),
    Ended(TcpIoIssue),
}

pub struct TcpNode;

impl TcpNode {
    pub fn exchange(
        &self,
        target: TargetServer,
        timeout: Duration,
        query: &DnsWireQuery,
    ) -> TcpSnap {
        let (mut stream, connect_time) = match connect_stream(target, timeout) {
            ConnectStep::Ready {
                stream,
                connect_time,
            } => (stream, connect_time),
            ConnectStep::Failed { elapsed, reason } => {
                return TcpSnap::Failed(TcpIssue::Connect { elapsed, reason });
            }
        };

        let (len_buf, first_chunk_len, first_byte_time) =
            match send_and_await_first_byte(&mut stream, query) {
                FirstByteStep::Received {
                    len_buf,
                    first_chunk_len,
                    first_byte_time,
                } => (len_buf, first_chunk_len, first_byte_time),
                FirstByteStep::Failed { elapsed, reason } => {
                    return TcpSnap::Failed(TcpIssue::FirstByte {
                        connect: connect_time,
                        elapsed,
                        reason,
                    });
                }
            };

        read_transfer(
            &mut stream,
            len_buf,
            first_chunk_len,
            connect_time,
            first_byte_time,
        )
    }
}

fn connect_stream(target: TargetServer, timeout: Duration) -> ConnectStep {
    let remote_addr = target.socket_addr();
    let start = Instant::now();

    let stream = match TcpStream::connect_timeout(&remote_addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            return ConnectStep::Failed {
                elapsed: start.elapsed(),
                reason: classify_io_error(e),
            };
        }
    };
    let connect_time = start.elapsed();

    let _ = stream.set_nodelay(true);
    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
        return ConnectStep::Failed {
            elapsed: connect_time,
            reason: classify_io_error(e),
        };
    }
    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        return ConnectStep::Failed {
            elapsed: connect_time,
            reason: classify_io_error(e),
        };
    }

    ConnectStep::Ready {
        stream,
        connect_time,
    }
}

fn send_and_await_first_byte(stream: &mut TcpStream, query: &DnsWireQuery) -> FirstByteStep {
    let query_bytes = query.as_bytes();
    let query_len = (query_bytes.len() as u16).to_be_bytes();
    let mut framed_query = Vec::with_capacity(2 + query_bytes.len());
    framed_query.extend_from_slice(&query_len);
    framed_query.extend_from_slice(query_bytes);

    let start = Instant::now();

    if let Err(e) = stream.write_all(&framed_query) {
        return FirstByteStep::Failed {
            elapsed: start.elapsed(),
            reason: classify_io_error(e),
        };
    }

    let mut len_buf = [0u8; 2];
    match read_chunk(stream, &mut len_buf) {
        ReadStep::Bytes(first_chunk_len) => FirstByteStep::Received {
            len_buf,
            first_chunk_len,
            first_byte_time: start.elapsed(),
        },
        ReadStep::Ended(reason) => FirstByteStep::Failed {
            elapsed: start.elapsed(),
            reason,
        },
    }
}

fn read_transfer(
    stream: &mut TcpStream,
    mut len_buf: [u8; 2],
    first_chunk_len: usize,
    connect: Duration,
    first_byte: Duration,
) -> TcpSnap {
    let start = Instant::now();

    if first_chunk_len == 1
        && let ReadStep::Ended(reason) = read_chunk(stream, &mut len_buf[1..2])
    {
        return TcpSnap::Failed(TcpIssue::Transfer {
            timings: TcpTimings {
                connect,
                first_byte,
                transfer: start.elapsed(),
            },
            reason: TransferIssue::IncompleteLengthHeader(reason),
        });
    }

    let expected_bytes = u16::from_be_bytes(len_buf) as usize;
    if expected_bytes == 0 {
        return TcpSnap::Failed(TcpIssue::Transfer {
            timings: TcpTimings {
                connect,
                first_byte,
                transfer: start.elapsed(),
            },
            reason: TransferIssue::ZeroLengthHeader,
        });
    }

    let mut buf = vec![0u8; expected_bytes];
    let mut received_bytes = 0;

    while received_bytes < expected_bytes {
        match read_chunk(stream, &mut buf[received_bytes..]) {
            ReadStep::Bytes(n) => {
                received_bytes += n;
            }
            ReadStep::Ended(reason) => {
                let timings = TcpTimings {
                    connect,
                    first_byte,
                    transfer: start.elapsed(),
                };
                if received_bytes == 0 {
                    return TcpSnap::Failed(TcpIssue::Transfer {
                        timings,
                        reason: TransferIssue::EmptyPayload {
                            expected_bytes,
                            reason,
                        },
                    });
                }
                buf.truncate(received_bytes);
                return TcpSnap::IncompletePayload {
                    salvaged: buf.into_boxed_slice(),
                    expected_bytes,
                    timings,
                    reason,
                };
            }
        }
    }

    TcpSnap::Received {
        payload: buf.into_boxed_slice(),
        timings: TcpTimings {
            connect,
            first_byte,
            transfer: start.elapsed(),
        },
    }
}

fn read_chunk(stream: &mut TcpStream, buf: &mut [u8]) -> ReadStep {
    loop {
        match stream.read(buf) {
            Ok(0) => return ReadStep::Ended(TcpIoIssue::UnexpectedEof),
            Ok(n) => return ReadStep::Bytes(n),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return ReadStep::Ended(classify_io_error(e)),
        }
    }
}

fn classify_io_error(err: io::Error) -> TcpIoIssue {
    match err.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => TcpIoIssue::TimedOut,
        ErrorKind::ConnectionRefused => TcpIoIssue::ConnectionRefused,
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => {
            TcpIoIssue::ConnectionReset
        }
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => {
            TcpIoIssue::NetworkUnreachable
        }
        _ => TcpIoIssue::Unknown(err),
    }
}
