use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;

use dns_tester::dns_core;
use dns_tester::random_node::RandomNode;
use dns_tester::tcp_node::{TcpIoIssue, TcpIssue, TcpNode, TcpSnap, TransferIssue};
use dns_tester::udp_node::{UdpNode, UdpSnap};
use dns_tester::validation_core::{self, ValidationSnap};

#[test]
fn tcp_node_salvages_incomplete_payload_on_unexpected_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr_str = listener.local_addr().unwrap().to_string();

    // "Злой" сервер: читает запрос, обещает 100 байт ответа, но шлёт только 24 и закрывает сокет
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut req_buf = [0u8; 512];
        let _ = stream.read(&mut req_buf);

        let mut frame = Vec::new();
        frame.extend_from_slice(&100u16.to_be_bytes()); // Обещаем 100 байт
        frame.extend_from_slice(&[0xAA; 24]); // Реально отдаём только 24 байта
        stream.write_all(&frame).unwrap();
        // При выходе из области видимости stream закрывается (отправляет FIN / EOF)
    });

    let ValidationSnap::Valid {
        target,
        domain,
        timeout,
    } = validation_core::validate(&addr_str, None, Some("1000"))
    else {
        panic!("Expected Valid target");
    };

    let query = dns_core::encode_query(&domain, RandomNode.next_query_id());
    let snap = TcpNode.exchange(target, timeout, &query);
    server_handle.join().unwrap();

    let TcpSnap::IncompletePayload {
        salvaged,
        expected_bytes,
        reason,
        ..
    } = snap
    else {
        panic!("Expected TcpSnap::IncompletePayload");
    };

    assert_eq!(expected_bytes, 100);
    assert_eq!(salvaged.len(), 24);
    assert!(salvaged.iter().all(|&b| b == 0xAA));
    assert!(matches!(reason, TcpIoIssue::UnexpectedEof));
}

#[test]
fn tcp_node_detects_zero_length_header() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr_str = listener.local_addr().unwrap().to_string();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut req_buf = [0u8; 512];
        let _ = stream.read(&mut req_buf);

        // Шлём заголовок длины 0x0000
        stream.write_all(&0u16.to_be_bytes()).unwrap();
    });

    let ValidationSnap::Valid {
        target,
        domain,
        timeout,
    } = validation_core::validate(&addr_str, None, Some("1000"))
    else {
        panic!("Expected Valid target");
    };

    let query = dns_core::encode_query(&domain, RandomNode.next_query_id());
    let snap = TcpNode.exchange(target, timeout, &query);
    server_handle.join().unwrap();

    assert!(matches!(
        snap,
        TcpSnap::Failed(TcpIssue::Transfer {
            reason: TransferIssue::ZeroLengthHeader,
            ..
        })
    ));
}

#[test]
fn udp_node_exchanges_payload_over_loopback() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr_str = server_socket.local_addr().unwrap().to_string();

    let server_handle = thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (len, client_addr) = server_socket.recv_from(&mut buf).unwrap();
        assert!(len >= 12);
        // Эхо-ответ теме же байтами
        server_socket.send_to(&buf[..len], client_addr).unwrap();
    });

    let ValidationSnap::Valid {
        target,
        domain,
        timeout,
    } = validation_core::validate(&addr_str, None, Some("1000"))
    else {
        panic!("Expected Valid target");
    };

    let query = dns_core::encode_query(&domain, RandomNode.next_query_id());
    let snap = UdpNode.exchange(target, timeout, &query);
    server_handle.join().unwrap();

    let UdpSnap::Received { payload, .. } = snap else {
        panic!("Expected UdpSnap::Received");
    };

    assert_eq!(&*payload, query.as_bytes());
}
