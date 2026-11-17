use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::thread;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record};

use dns_tester::cli_node::CliNode;
use dns_tester::cli_parse_core::CliIssue;
use dns_tester::probe_hub::{AppIssue, AppSnap, ProbeHub};
use dns_tester::random_node::RandomNode;
use dns_tester::tcp_node::TcpNode;
use dns_tester::udp_node::UdpNode;
use dns_tester::validation_core::ValidationIssue;

fn make_hub() -> ProbeHub {
    ProbeHub {
        cli: CliNode,
        random: RandomNode,
        udp: UdpNode,
        tcp: TcpNode,
    }
}

fn args(slice: &[&str]) -> Box<[String]> {
    slice
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn build_dns_reply(query_id: u16, truncated: bool) -> Vec<u8> {
    let name = Name::from_ascii("example.com.").unwrap();
    let mut msg = Message::new(query_id, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_available = true;
    msg.metadata.truncation = truncated;
    msg.metadata.response_code = ResponseCode::NoError;
    msg.answers.push(Record::from_rdata(
        name,
        60,
        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
    ));
    msg.to_vec().unwrap()
}

#[test]
fn hub_aborts_on_cli_and_validation_issues() {
    let hub = make_hub();

    assert!(matches!(
        hub.run_with_args(&args(&["--help"])),
        AppSnap::Aborted(AppIssue::Cli(CliIssue::HelpRequested))
    ));

    assert!(matches!(
        hub.run_with_args(&args(&["not_an_ip"])),
        AppSnap::Aborted(AppIssue::Validation(ValidationIssue::Target(_)))
    ));
}

#[test]
fn hub_auto_mode_falls_back_from_truncated_udp_to_tcp() {
    let udp_server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp_server.local_addr().unwrap();
    let tcp_listener = TcpListener::bind(addr).unwrap();

    // 1. UDP-сервер отвечает усечённым пакетом (TC=1)
    let udp_handle = thread::spawn(move || {
        let mut req = [0u8; 512];
        let (len, client) = udp_server.recv_from(&mut req).unwrap();
        assert!(len >= 12);
        let query_id = u16::from_be_bytes([req[0], req[1]]);
        let reply = build_dns_reply(query_id, true); // TC = 1!
        udp_server.send_to(&reply, client).unwrap();
    });

    // 2. TCP-сервер ждёт фоллбэк-запрос и отдаёт полный ответ (TC=0)
    let tcp_handle = thread::spawn(move || {
        let (mut stream, _) = tcp_listener.accept().unwrap();
        let mut req = [0u8; 512];
        let len = stream.read(&mut req).unwrap();
        assert!(len >= 14);
        // В TCP первые 2 байта — длина, а байты [2, 3] — QueryId
        let query_id = u16::from_be_bytes([req[2], req[3]]);
        let reply = build_dns_reply(query_id, false); // TC = 0!

        let mut framed = Vec::with_capacity(2 + reply.len());
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).unwrap();
    });

    let hub = make_hub();
    let snap = hub.run_with_args(&args(&[&addr.to_string(), "--auto", "--ru"]));

    udp_handle.join().unwrap();
    tcp_handle.join().unwrap();

    assert!(matches!(snap, AppSnap::Completed));
}
