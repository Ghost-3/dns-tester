use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use dns_tester::dns_core::{self, DnsParseSnap, IdSnap, MalformedIssue};
use dns_tester::primitives::{DnsRcode, DnsRecordData};
use dns_tester::random_node::RandomNode;

/// Вспомогательный сборщик тестового DNS-ответа с двумя A-записями.
fn build_response_bytes(id: u16, truncated: bool) -> Vec<u8> {
    let name = Name::from_ascii("example.com.").unwrap();
    let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_available = true;
    msg.metadata.truncation = truncated;
    msg.metadata.response_code = ResponseCode::NoError;

    msg.queries.push(Query::query(name.clone(), RecordType::A));

    msg.answers.push(Record::from_rdata(
        name.clone(),
        60,
        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
    ));
    msg.answers.push(Record::from_rdata(
        name,
        120,
        RData::A(A(Ipv4Addr::new(93, 184, 216, 35))),
    ));

    msg.to_vec().unwrap()
}

#[test]
fn parses_complete_authentic_response() {
    let query_id = RandomNode.next_query_id();
    let raw = build_response_bytes(query_id.as_u16(), false);

    let DnsParseSnap::Complete(IdSnap::Authentic(packet)) =
        dns_core::parse_response(&raw, query_id)
    else {
        panic!("Expected Complete(Authentic)");
    };

    assert!(matches!(packet.rcode, DnsRcode::NoError));
    assert!(packet.recursion_available);
    assert_eq!(packet.records.len(), 2);
    assert!(matches!(
        packet.records[0].data,
        DnsRecordData::A(ip) if ip == Ipv4Addr::new(93, 184, 216, 34)
    ));
}

#[test]
fn detects_id_mismatch_while_preserving_all_records() {
    let expected_id = RandomNode.next_query_id();
    let spoofed_id = expected_id.as_u16().wrapping_add(1);
    let raw = build_response_bytes(spoofed_id, false);

    let DnsParseSnap::Complete(IdSnap::IdMismatch {
        expected,
        received,
        packet,
    }) = dns_core::parse_response(&raw, expected_id)
    else {
        panic!("Expected Complete(IdMismatch)");
    };

    assert_eq!(expected.as_u16(), expected_id.as_u16());
    assert_eq!(received, spoofed_id);
    assert_eq!(packet.records.len(), 2);
}

#[test]
fn truncated_packet_cut_mid_record_still_triggers_truncated_and_salvages_first_record() {
    let query_id = RandomNode.next_query_id();
    let mut raw = build_response_bytes(query_id.as_u16(), true);

    // Отрубаем последние 5 байт (прямо посреди второй A-записи)
    raw.truncate(raw.len() - 5);

    let DnsParseSnap::Truncated(IdSnap::Authentic(packet)) =
        dns_core::parse_response(&raw, query_id)
    else {
        panic!("Expected Truncated(Authentic)");
    };

    // Первая запись полностью спасена, несмотря на обрубленную вторую!
    assert_eq!(packet.records.len(), 1);
    assert!(matches!(
        packet.records[0].data,
        DnsRecordData::A(ip) if ip == Ipv4Addr::new(93, 184, 216, 34)
    ));
}

#[test]
fn corrupted_body_without_tc_flag_salvages_first_record_and_reports_exact_offset() {
    let query_id = RandomNode.next_query_id();
    let mut raw = build_response_bytes(query_id.as_u16(), false);
    let full_len = raw.len();

    // Отрубаем последние 4 байта (IP-адрес второй записи), TC=0
    raw.truncate(full_len - 4);

    let DnsParseSnap::Malformed(MalformedIssue::CorruptedBody {
        salvaged: IdSnap::Authentic(packet),
        error_offset,
    }) = dns_core::parse_response(&raw, query_id)
    else {
        panic!("Expected Malformed(CorruptedBody)");
    };

    assert_eq!(packet.records.len(), 1);
    assert!(error_offset > 12 && error_offset < raw.len());
}

#[test]
fn rejects_short_header_under_12_bytes() {
    let query_id = RandomNode.next_query_id();
    let short_raw = [0u8; 7];

    let DnsParseSnap::Malformed(MalformedIssue::ShortHeader { received_bytes }) =
        dns_core::parse_response(&short_raw, query_id)
    else {
        panic!("Expected Malformed(ShortHeader)");
    };

    assert_eq!(received_bytes, 7);
}
