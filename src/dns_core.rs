//! Чистое расчётное ядро: кодирование запросов и пошаговый разбор ответов DNS (RFC 1035)
//! без знания о сети и сокетах, с сохранением данных из усечённых и повреждённых пакетов.

use hickory_proto::op::{Header, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

use crate::primitives::{DnsPacket, DnsRcode, DnsRecord, DnsRecordData, DomainName, QueryId};

const DNS_HEADER_LEN: usize = 12;

/// Биографический примитив байтового DNS-запроса: рождается исключительно в `dns_core`.
pub struct DnsWireQuery(Box<[u8]>);

impl DnsWireQuery {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub enum IdSnap {
    Authentic(DnsPacket),
    IdMismatch {
        expected: QueryId,
        received: u16,
        packet: DnsPacket,
    },
}

pub enum DnsParseSnap {
    Complete(IdSnap),
    Truncated(IdSnap),
    Malformed(MalformedIssue),
}

pub enum MalformedIssue {
    ShortHeader {
        received_bytes: usize,
    },
    CorruptedBody {
        salvaged: IdSnap,
        error_offset: usize,
    },
}

enum BodyDecodeStep {
    Complete,
    Corrupted { error_offset: usize },
}

/// Формирует стандартный запрос типа `A` без EDNS0 (`OPT`), чтобы ответ сервера в UDP
/// укладывался в классические 512 байт и не подвергался IP-фрагментации.
pub fn encode_query(domain: &DomainName, id: QueryId) -> DnsWireQuery {
    let mut message = Message::new(id.as_u16(), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message
        .queries
        .push(Query::query(domain.as_name().clone(), RecordType::A));

    let bytes = message
        .to_vec()
        .expect("Encoding a validated DomainName into a DNS query cannot fail");

    DnsWireQuery(bytes.into_boxed_slice())
}

pub fn parse_response(raw: &[u8], expected_id: QueryId) -> DnsParseSnap {
    if raw.len() < DNS_HEADER_LEN {
        return DnsParseSnap::Malformed(MalformedIssue::ShortHeader {
            received_bytes: raw.len(),
        });
    }

    let mut decoder = BinDecoder::new(raw);
    let header = match Header::read(&mut decoder) {
        Ok(h) => h,
        Err(_) => {
            return DnsParseSnap::Malformed(MalformedIssue::ShortHeader {
                received_bytes: raw.len(),
            });
        }
    };

    let mut salvaged_records = Vec::new();
    let body_step = decode_body(&mut decoder, &header, &mut salvaged_records);

    let packet = DnsPacket {
        rcode: map_rcode(header.metadata.response_code),
        recursion_available: header.metadata.recursion_available,
        records: salvaged_records.into_boxed_slice(),
    };

    let id_snap = if header.metadata.id == expected_id.as_u16() {
        IdSnap::Authentic(packet)
    } else {
        IdSnap::IdMismatch {
            expected: expected_id,
            received: header.metadata.id,
            packet,
        }
    };

    // Реальные DNS-серверы при усечении UDP (TC=1) могут оборвать пакет прямо посреди записи,
    // не уменьшив ANCOUNT в заголовке. Поэтому флаг TC=1 проверяется до BodyDecodeStep::Corrupted,
    // чтобы ProbeHub гарантированно запустил фоллбэк на TCP в режиме Auto.
    if header.metadata.truncation {
        return DnsParseSnap::Truncated(id_snap);
    }

    match body_step {
        BodyDecodeStep::Complete => DnsParseSnap::Complete(id_snap),
        BodyDecodeStep::Corrupted { error_offset } => {
            DnsParseSnap::Malformed(MalformedIssue::CorruptedBody {
                salvaged: id_snap,
                error_offset,
            })
        }
    }
}

fn decode_body<'a>(
    decoder: &mut BinDecoder<'a>,
    header: &Header,
    answers_out: &mut Vec<DnsRecord>,
) -> BodyDecodeStep {
    for _ in 0..header.counts.queries {
        let record_start = decoder.index();
        if Query::read(decoder).is_err() {
            return BodyDecodeStep::Corrupted {
                error_offset: record_start,
            };
        }
    }

    for _ in 0..header.counts.answers {
        let record_start = decoder.index();
        match Record::read(decoder) {
            Ok(record) => answers_out.push(map_record(record)),
            Err(_) => {
                return BodyDecodeStep::Corrupted {
                    error_offset: record_start,
                };
            }
        }
    }

    let trailing_records =
        (header.counts.authorities as usize) + (header.counts.additionals as usize);
    for _ in 0..trailing_records {
        let record_start = decoder.index();
        if Record::read(decoder).is_err() {
            return BodyDecodeStep::Corrupted {
                error_offset: record_start,
            };
        }
    }

    BodyDecodeStep::Complete
}

fn map_rcode(code: ResponseCode) -> DnsRcode {
    match code {
        ResponseCode::NoError => DnsRcode::NoError,
        ResponseCode::FormErr => DnsRcode::FormErr,
        ResponseCode::ServFail => DnsRcode::ServFail,
        ResponseCode::NXDomain => DnsRcode::NxDomain,
        ResponseCode::NotImp => DnsRcode::NotImp,
        ResponseCode::Refused => DnsRcode::Refused,
        other => DnsRcode::Unknown(u16::from(other)),
    }
}

fn map_record(record: Record) -> DnsRecord {
    let name = record.name.to_ascii();
    let ttl = record.ttl;
    let rtype_u16 = u16::from(record.record_type());

    let data = match record.data {
        RData::A(a) => DnsRecordData::A(a.0),
        RData::AAAA(aaaa) => DnsRecordData::Aaaa(aaaa.0),
        RData::CNAME(cname) => DnsRecordData::Cname(cname.0.to_ascii()),
        _ => DnsRecordData::Unknown {
            record_type: rtype_u16,
        },
    };

    DnsRecord { name, ttl, data }
}
