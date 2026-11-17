//! Чистое расчётное ядро: статическая двуязычная локализация всех состояний системы
//! через исчерпывающий паттерн-матчинг под контролем компилятора (без `_ =>`).

use crate::cli_parse_core::CliIssue;
use crate::dns_core::{DnsParseSnap, IdSnap, MalformedIssue};
use crate::primitives::{
    DnsPacket, DnsRcode, DnsRecord, DnsRecordData, DomainName, Duration, Lang, ProbeMode, QueryId,
    TargetServer, TcpTimings,
};
use crate::tcp_node::{TcpIoIssue, TcpIssue, TransferIssue};
use crate::udp_node::{UdpIoIssue, UdpIssue};
use crate::validation_core::{DomainIssue, TargetIssue, TimeoutIssue, ValidationIssue};

pub fn cli_issue(lang: Lang, issue: &CliIssue) -> String {
    match (lang, issue) {
        (Lang::En, CliIssue::HelpRequested) => concat!(
            "Usage: dns-tester <IP[:PORT]> [DOMAIN] [TIMEOUT_MS] [FLAGS]\n",
            "Flags:\n",
            "  --auto   UDP first, fallback to TCP if truncated (default)\n",
            "  --udp    Force UDP only\n",
            "  --tcp    Force TCP only\n",
            "  --both   Run both UDP and TCP\n",
            "  --en     English output (default)\n",
            "  --ru     Russian output\n",
            "  -h, --help  Show this help"
        )
        .to_string(),
        (Lang::Ru, CliIssue::HelpRequested) => concat!(
            "Использование: dns-tester <IP[:PORT]> [ДОМЕН] [ТАЙМАУТ_МС] [ФЛАГИ]\n",
            "Флаги:\n",
            "  --auto   Сначала UDP, переход на TCP при усечении (по умолчанию)\n",
            "  --udp    Только UDP\n",
            "  --tcp    Только TCP\n",
            "  --both   Оба протокола (UDP и TCP)\n",
            "  --en     Вывод на английском (по умолчанию)\n",
            "  --ru     Вывод на русском\n",
            "  -h, --help  Показать эту справку"
        )
        .to_string(),
        (Lang::En, CliIssue::MissingArguments) => {
            "CLI Error: Missing target server IP. Use --help for usage.".to_string()
        }
        (Lang::Ru, CliIssue::MissingArguments) => {
            "Ошибка CLI: Не указан IP целевого сервера. Используйте --help для справки.".to_string()
        }
        (Lang::En, CliIssue::UnknownFlag(flag)) => format!("CLI Error: Unknown flag '{flag}'."),

        (Lang::Ru, CliIssue::UnknownFlag(flag)) => {
            format!("Ошибка CLI: Неизвестный флаг '{flag}'.")
        }
        (Lang::En, CliIssue::ConflictingModes) => {
            "CLI Error: Conflicting transport mode flags specified.".to_string()
        }
        (Lang::Ru, CliIssue::ConflictingModes) => {
            "Ошибка CLI: Указаны конфликтующие флаги режима транспорта.".to_string()
        }
        (Lang::En, CliIssue::ConflictingLangs) => {
            "CLI Error: Conflicting language flags (--en and --ru) specified.".to_string()
        }
        (Lang::Ru, CliIssue::ConflictingLangs) => {
            "Ошибка CLI: Указаны конфликтующие флаги языка (--en и --ru).".to_string()
        }
        (Lang::En, CliIssue::TooManyArguments(arg)) => {
            format!("CLI Error: Unexpected extra positional argument '{arg}'.")
        }
        (Lang::Ru, CliIssue::TooManyArguments(arg)) => {
            format!("Ошибка CLI: Лишний позиционный аргумент '{arg}'.")
        }
    }
}

pub fn validation_issue(lang: Lang, issue: &ValidationIssue) -> String {
    match (lang, issue) {
        (Lang::En, ValidationIssue::Target(TargetIssue::Empty)) => {
            "Validation Error: Target server address cannot be empty.".to_string()
        }
        (Lang::Ru, ValidationIssue::Target(TargetIssue::Empty)) => {
            "Ошибка валидации: Адрес сервера не может быть пустым.".to_string()
        }
        (Lang::En, ValidationIssue::Target(TargetIssue::ZeroPort)) => {
            "Validation Error: Target port cannot be 0.".to_string()
        }
        (Lang::Ru, ValidationIssue::Target(TargetIssue::ZeroPort)) => {
            "Ошибка валидации: Порт сервера не может быть равен 0.".to_string()
        }
        (Lang::En, ValidationIssue::Target(TargetIssue::InvalidAddress(raw))) => {
            format!("Validation Error: Invalid target IP or socket address '{raw}'.")
        }
        (Lang::Ru, ValidationIssue::Target(TargetIssue::InvalidAddress(raw))) => {
            format!("Ошибка валидации: Некорректный IP или адрес сокета '{raw}'.")
        }
        (Lang::En, ValidationIssue::Domain(DomainIssue::Empty)) => {
            "Validation Error: Domain name cannot be empty.".to_string()
        }
        (Lang::Ru, ValidationIssue::Domain(DomainIssue::Empty)) => {
            "Ошибка валидации: Доменное имя не может быть пустым.".to_string()
        }
        (Lang::En, ValidationIssue::Domain(DomainIssue::InvalidSyntax(raw))) => {
            format!("Validation Error: Invalid domain name '{raw}'.")
        }
        (Lang::Ru, ValidationIssue::Domain(DomainIssue::InvalidSyntax(raw))) => {
            format!("Ошибка валидации: Некорректное доменное имя '{raw}'.")
        }
        (Lang::En, ValidationIssue::Timeout(TimeoutIssue::NotANumber(raw))) => {
            format!("Validation Error: Timeout '{raw}' is not a valid positive integer (ms).")
        }
        (Lang::Ru, ValidationIssue::Timeout(TimeoutIssue::NotANumber(raw))) => {
            format!(
                "Ошибка валидации: Таймаут '{raw}' не является целым положительным числом (мс)."
            )
        }
        (Lang::En, ValidationIssue::Timeout(TimeoutIssue::Zero)) => {
            "Validation Error: Timeout must be greater than 0 ms.".to_string()
        }
        (Lang::Ru, ValidationIssue::Timeout(TimeoutIssue::Zero)) => {
            "Ошибка валидации: Таймаут должен быть больше 0 мс.".to_string()
        }
        (
            Lang::En,
            ValidationIssue::Timeout(TimeoutIssue::TooLarge {
                provided_ms,
                max_ms,
            }),
        ) => {
            format!("Validation Error: Timeout {provided_ms} ms exceeds maximum ({max_ms} ms).")
        }
        (
            Lang::Ru,
            ValidationIssue::Timeout(TimeoutIssue::TooLarge {
                provided_ms,
                max_ms,
            }),
        ) => {
            format!("Ошибка валидации: Таймаут {provided_ms} мс превышает максимум ({max_ms} мс).")
        }
    }
}

pub fn udp_received(lang: Lang, rtt: Duration) -> String {
    let rtt_ms = as_ms(rtt);
    match lang {
        Lang::En => format!("[UDP] Response received in {rtt_ms:.2} ms"),
        Lang::Ru => format!("[UDP] Ответ получен за {rtt_ms:.2} мс"),
    }
}

pub fn udp_issue(lang: Lang, issue: &UdpIssue) -> String {
    match (lang, issue) {
        (Lang::En, UdpIssue::SetupFailed { reason }) => {
            format!(
                "[UDP] Socket setup failed: {}",
                format_udp_io_issue(Lang::En, reason)
            )
        }
        (Lang::Ru, UdpIssue::SetupFailed { reason }) => {
            format!(
                "[UDP] Сбой подготовки сокета: {}",
                format_udp_io_issue(Lang::Ru, reason)
            )
        }
        (Lang::En, UdpIssue::ExchangeFailed { elapsed, reason }) => {
            let ms = as_ms(*elapsed);
            format!(
                "[UDP] Failed after {ms:.2} ms: {}",
                format_udp_io_issue(Lang::En, reason)
            )
        }
        (Lang::Ru, UdpIssue::ExchangeFailed { elapsed, reason }) => {
            let ms = as_ms(*elapsed);
            format!(
                "[UDP] Сбой через {ms:.2} мс: {}",
                format_udp_io_issue(Lang::Ru, reason)
            )
        }
    }
}

pub fn tcp_received(lang: Lang, timings: &TcpTimings) -> String {
    let timings_str = format_tcp_timings(lang, timings);
    match lang {
        Lang::En => format!("[TCP] Response received ({timings_str})"),
        Lang::Ru => format!("[TCP] Ответ получен ({timings_str})"),
    }
}

pub fn tcp_incomplete(
    lang: Lang,
    timings: &TcpTimings,
    received_bytes: usize,
    expected_bytes: usize,
    reason: &TcpIoIssue,
) -> String {
    let timings_str = format_tcp_timings(lang, timings);
    let reason_str = format_tcp_io_issue(lang, reason);
    match lang {
        Lang::En => format!(
            "[TCP] WARNING: Incomplete payload ({received_bytes} of {expected_bytes} bytes, \
             reason: {reason_str}; {timings_str}). Salvaging received bytes..."
        ),
        Lang::Ru => format!(
            "[TCP] ВНИМАНИЕ: Неполный пакет ({received_bytes} из {expected_bytes} байт, \
             причина: {reason_str}; {timings_str}). Спасаем полученные байты..."
        ),
    }
}

pub fn tcp_issue(lang: Lang, issue: &TcpIssue) -> String {
    match (lang, issue) {
        (Lang::En, TcpIssue::Connect { elapsed, reason }) => {
            let ms = as_ms(*elapsed);
            let reason_str = format_tcp_io_issue(Lang::En, reason);
            format!("[TCP] Connect failed after {ms:.2} ms: {reason_str}")
        }
        (Lang::Ru, TcpIssue::Connect { elapsed, reason }) => {
            let ms = as_ms(*elapsed);
            let reason_str = format_tcp_io_issue(Lang::Ru, reason);
            format!("[TCP] Сбой подключения через {ms:.2} мс: {reason_str}")
        }
        (
            Lang::En,
            TcpIssue::FirstByte {
                connect,
                elapsed,
                reason,
            },
        ) => {
            let conn_ms = as_ms(*connect);
            let fail_ms = as_ms(*elapsed);
            let reason_str = format_tcp_io_issue(Lang::En, reason);
            format!(
                "[TCP] Failed awaiting first byte (connect: {conn_ms:.2} ms, \
                 failed after: {fail_ms:.2} ms): {reason_str}"
            )
        }
        (
            Lang::Ru,
            TcpIssue::FirstByte {
                connect,
                elapsed,
                reason,
            },
        ) => {
            let conn_ms = as_ms(*connect);
            let fail_ms = as_ms(*elapsed);
            let reason_str = format_tcp_io_issue(Lang::Ru, reason);
            format!(
                "[TCP] Сбой ожидания первого байта (коннект: {conn_ms:.2} мс, \
                 сбой через: {fail_ms:.2} мс): {reason_str}"
            )
        }
        (Lang::En, TcpIssue::Transfer { timings, reason }) => {
            let timings_str = format_tcp_timings(Lang::En, timings);
            let reason_str = format_transfer_issue(Lang::En, reason);
            format!("[TCP] Transfer failed ({timings_str}): {reason_str}")
        }
        (Lang::Ru, TcpIssue::Transfer { timings, reason }) => {
            let timings_str = format_tcp_timings(Lang::Ru, timings);
            let reason_str = format_transfer_issue(Lang::Ru, reason);
            format!("[TCP] Сбой передачи данных ({timings_str}): {reason_str}")
        }
    }
}

pub fn dns_outcome(lang: Lang, snap: &DnsParseSnap) -> String {
    match (lang, snap) {
        (Lang::En, DnsParseSnap::Complete(id_snap)) => {
            format!(
                "  Status: Complete packet\n{}",
                format_id_snap(Lang::En, id_snap)
            )
        }
        (Lang::Ru, DnsParseSnap::Complete(id_snap)) => {
            format!(
                "  Статус: Полный пакет\n{}",
                format_id_snap(Lang::Ru, id_snap)
            )
        }
        (Lang::En, DnsParseSnap::Truncated(id_snap)) => {
            format!(
                "  Status: Truncated packet (TC=1)\n{}",
                format_id_snap(Lang::En, id_snap)
            )
        }
        (Lang::Ru, DnsParseSnap::Truncated(id_snap)) => {
            format!(
                "  Статус: Усечённый пакет (TC=1)\n{}",
                format_id_snap(Lang::Ru, id_snap)
            )
        }
        (Lang::En, DnsParseSnap::Malformed(MalformedIssue::ShortHeader { received_bytes })) => {
            format!(
                "  Status: Malformed DNS packet (header too short: {received_bytes} bytes, \
                 minimum is 12 bytes)"
            )
        }
        (Lang::Ru, DnsParseSnap::Malformed(MalformedIssue::ShortHeader { received_bytes })) => {
            format!(
                "  Статус: Повреждённый DNS-пакет (короткий заголовок: {received_bytes} байт \
                 при минимуме 12 байт)"
            )
        }
        (
            Lang::En,
            DnsParseSnap::Malformed(MalformedIssue::CorruptedBody {
                salvaged,
                error_offset,
            }),
        ) => {
            format!(
                "  Status: Malformed DNS body (corrupted at byte offset {error_offset}, \
                 showing salvaged data)\n{}",
                format_id_snap(Lang::En, salvaged)
            )
        }
        (
            Lang::Ru,
            DnsParseSnap::Malformed(MalformedIssue::CorruptedBody {
                salvaged,
                error_offset,
            }),
        ) => {
            format!(
                "  Статус: Повреждено тело DNS-пакета (ошибка на смещении {error_offset} байт, \
                 показаны спасённые данные)\n{}",
                format_id_snap(Lang::Ru, salvaged)
            )
        }
    }
}

pub fn tcp_fallback_notice(lang: Lang) -> String {
    match lang {
        Lang::En => "[Auto] UDP response was truncated (TC=1). Retrying over TCP...".to_string(),
        Lang::Ru => "[Auto] UDP-ответ усечён (TC=1). Повторный запрос по TCP...".to_string(),
    }
}

pub fn tcp_truncated_anomaly(lang: Lang) -> String {
    match lang {
        Lang::En => {
            "[TCP] ANOMALY: Server set TC=1 (Truncated) flag inside a TCP response!".to_string()
        }
        Lang::Ru => {
            "[TCP] АНОМАЛИЯ: Сервер выставил флаг TC=1 (Truncated) внутри TCP-ответа!".to_string()
        }
    }
}

fn format_udp_io_issue(lang: Lang, issue: &UdpIoIssue) -> String {
    match (lang, issue) {
        (Lang::En, UdpIoIssue::TimedOut) => "Timed out".to_string(),
        (Lang::Ru, UdpIoIssue::TimedOut) => "Превышен таймаут ожидания".to_string(),
        (Lang::En, UdpIoIssue::ConnectionRefused) => {
            "Connection refused (ICMP Port Unreachable)".to_string()
        }
        (Lang::Ru, UdpIoIssue::ConnectionRefused) => {
            "Соединение отклонено (ICMP Port Unreachable)".to_string()
        }
        (Lang::En, UdpIoIssue::NetworkUnreachable) => "Network or host unreachable".to_string(),
        (Lang::Ru, UdpIoIssue::NetworkUnreachable) => "Сеть или хост недоступны".to_string(),
        (Lang::En, UdpIoIssue::Unknown(err)) => format!("OS I/O error ({err})"),
        (Lang::Ru, UdpIoIssue::Unknown(err)) => format!("Системная ошибка ввода-вывода ({err})"),
    }
}

fn format_tcp_io_issue(lang: Lang, issue: &TcpIoIssue) -> String {
    match (lang, issue) {
        (Lang::En, TcpIoIssue::TimedOut) => "Timed out".to_string(),
        (Lang::Ru, TcpIoIssue::TimedOut) => "Превышен таймаут".to_string(),
        (Lang::En, TcpIoIssue::ConnectionRefused) => "Connection refused".to_string(),
        (Lang::Ru, TcpIoIssue::ConnectionRefused) => "Соединение отклонено (RST)".to_string(),
        (Lang::En, TcpIoIssue::ConnectionReset) => "Connection reset by peer".to_string(),
        (Lang::Ru, TcpIoIssue::ConnectionReset) => "Соединение сброшено сервером".to_string(),
        (Lang::En, TcpIoIssue::NetworkUnreachable) => "Network or host unreachable".to_string(),
        (Lang::Ru, TcpIoIssue::NetworkUnreachable) => "Сеть или хост недоступны".to_string(),
        (Lang::En, TcpIoIssue::UnexpectedEof) => "Unexpected EOF (connection closed)".to_string(),
        (Lang::Ru, TcpIoIssue::UnexpectedEof) => {
            "Неожиданный конец потока (сервер закрыл соединение)".to_string()
        }
        (Lang::En, TcpIoIssue::Unknown(err)) => format!("OS I/O error ({err})"),
        (Lang::Ru, TcpIoIssue::Unknown(err)) => format!("Системная ошибка ввода-вывода ({err})"),
    }
}

fn format_transfer_issue(lang: Lang, issue: &TransferIssue) -> String {
    match (lang, issue) {
        (Lang::En, TransferIssue::IncompleteLengthHeader(io_issue)) => {
            format!(
                "Incomplete 2-byte length prefix ({})",
                format_tcp_io_issue(Lang::En, io_issue)
            )
        }
        (Lang::Ru, TransferIssue::IncompleteLengthHeader(io_issue)) => {
            format!(
                "Неполный 2-байтовый заголовок длины ({})",
                format_tcp_io_issue(Lang::Ru, io_issue)
            )
        }
        (Lang::En, TransferIssue::ZeroLengthHeader) => {
            "Server sent a zero-length TCP frame (0 bytes)".to_string()
        }
        (Lang::Ru, TransferIssue::ZeroLengthHeader) => {
            "Сервер прислал TCP-кадр нулевой длины (0 байт)".to_string()
        }
        (
            Lang::En,
            TransferIssue::EmptyPayload {
                expected_bytes,
                reason,
            },
        ) => {
            format!(
                "0 of {expected_bytes} payload bytes received ({})",
                format_tcp_io_issue(Lang::En, reason)
            )
        }
        (
            Lang::Ru,
            TransferIssue::EmptyPayload {
                expected_bytes,
                reason,
            },
        ) => {
            format!(
                "Получено 0 из {expected_bytes} байт тела пакета ({})",
                format_tcp_io_issue(Lang::Ru, reason)
            )
        }
    }
}

fn format_tcp_timings(lang: Lang, timings: &TcpTimings) -> String {
    let conn = as_ms(timings.connect);
    let fb = as_ms(timings.first_byte);
    let tr = as_ms(timings.transfer);
    let total = as_ms(timings.connect + timings.first_byte + timings.transfer);

    match lang {
        Lang::En => format!(
            "connect: {conn:.2} ms, first byte: {fb:.2} ms, transfer: {tr:.2} ms, total: {total:.2} ms"
        ),
        Lang::Ru => format!(
            "коннект: {conn:.2} мс, первый байт: {fb:.2} мс, передача: {tr:.2} мс, всего: {total:.2} мс"
        ),
    }
}

fn format_id_snap(lang: Lang, id_snap: &IdSnap) -> String {
    match (lang, id_snap) {
        (Lang::En, IdSnap::Authentic(packet)) => {
            format!("  Query ID: Authentic\n{}", format_packet(Lang::En, packet))
        }
        (Lang::Ru, IdSnap::Authentic(packet)) => {
            format!("  Query ID: Подлинный\n{}", format_packet(Lang::Ru, packet))
        }
        (
            Lang::En,
            IdSnap::IdMismatch {
                expected,
                received,
                packet,
            },
        ) => {
            let exp = expected.as_u16();
            format!(
                "  Query ID: MISMATCH (expected 0x{exp:04X}, received 0x{received:04X})\n{}",
                format_packet(Lang::En, packet)
            )
        }
        (
            Lang::Ru,
            IdSnap::IdMismatch {
                expected,
                received,
                packet,
            },
        ) => {
            let exp = expected.as_u16();
            format!(
                "  Query ID: НЕСОВПАДЕНИЕ (ожидался 0x{exp:04X}, получен 0x{received:04X})\n{}",
                format_packet(Lang::Ru, packet)
            )
        }
    }
}

fn format_packet(lang: Lang, packet: &DnsPacket) -> String {
    let rcode_str = format_rcode(packet.rcode);
    let ra_str = match (lang, packet.recursion_available) {
        (Lang::En, true) => "yes",
        (Lang::En, false) => "no (WARNING: recursion disabled)",
        (Lang::Ru, true) => "да",
        (Lang::Ru, false) => "нет (ВНИМАНИЕ: рекурсия отключена)",
    };

    let records_section = if packet.records.is_empty() {
        match lang {
            Lang::En => "  Records: none".to_string(),
            Lang::Ru => "  Записи: нет".to_string(),
        }
    } else {
        let formatted_records = packet
            .records
            .iter()
            .map(|r| format_record(lang, r))
            .collect::<Vec<_>>()
            .join("\n");

        match lang {
            Lang::En => format!("  Records ({}):\n{formatted_records}", packet.records.len()),
            Lang::Ru => format!("  Записи ({}):\n{formatted_records}", packet.records.len()),
        }
    };

    match lang {
        Lang::En => {
            format!("  RCODE: {rcode_str} | Recursion Available (RA): {ra_str}\n{records_section}")
        }
        Lang::Ru => {
            format!("  RCODE: {rcode_str} | Доступность рекурсии (RA): {ra_str}\n{records_section}")
        }
    }
}

fn format_rcode(rcode: DnsRcode) -> String {
    match rcode {
        DnsRcode::NoError => "NOERROR (0)".to_string(),
        DnsRcode::FormErr => "FORMERR (1)".to_string(),
        DnsRcode::ServFail => "SERVFAIL (2)".to_string(),
        DnsRcode::NxDomain => "NXDOMAIN (3)".to_string(),
        DnsRcode::NotImp => "NOTIMP (4)".to_string(),
        DnsRcode::Refused => "REFUSED (5)".to_string(),
        DnsRcode::Unknown(code) => format!("RCODE_{code}"),
    }
}

fn format_record(lang: Lang, record: &DnsRecord) -> String {
    let name = &record.name;
    let ttl = record.ttl;
    match (lang, &record.data) {
        (Lang::En | Lang::Ru, DnsRecordData::A(ipv4)) => {
            format!("    - {name} [TTL {ttl}s] A {ipv4}")
        }
        (Lang::En | Lang::Ru, DnsRecordData::Aaaa(ipv6)) => {
            format!("    - {name} [TTL {ttl}s] AAAA {ipv6}")
        }
        (Lang::En | Lang::Ru, DnsRecordData::Cname(cname)) => {
            format!("    - {name} [TTL {ttl}s] CNAME {cname}")
        }
        (Lang::En, DnsRecordData::Unknown { record_type }) => {
            format!("    - {name} [TTL {ttl}s] TYPE_{record_type} (unparsed)")
        }
        (Lang::Ru, DnsRecordData::Unknown { record_type }) => {
            format!("    - {name} [TTL {ttl}s] TYPE_{record_type} (не разобран)")
        }
    }
}

fn as_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

pub fn probe_banner(
    lang: Lang,
    target: TargetServer,
    domain: &DomainName,
    mode: ProbeMode,
    timeout: Duration,
    query_id: QueryId,
) -> String {
    let addr = target.socket_addr();
    let domain_str = domain.as_name().to_ascii();
    let mode_str = format_mode(lang, mode);
    let timeout_ms = timeout.as_millis();
    let id_u16 = query_id.as_u16();

    match lang {
        Lang::En => format!(
            "Probing A '{domain_str}' @ {addr} (mode: {mode_str}, timeout: {timeout_ms} ms, ID: 0x{id_u16:04X})"
        ),
        Lang::Ru => format!(
            "Запрос A '{domain_str}' к {addr} (режим: {mode_str}, таймаут: {timeout_ms} мс, ID: 0x{id_u16:04X})"
        ),
    }
}

fn format_mode(lang: Lang, mode: ProbeMode) -> &'static str {
    match (lang, mode) {
        (Lang::En, ProbeMode::Auto) => "Auto (UDP -> TCP)",
        (Lang::Ru, ProbeMode::Auto) => "Авто (UDP -> TCP)",
        (Lang::En | Lang::Ru, ProbeMode::ForceUdp) => "UDP",
        (Lang::En | Lang::Ru, ProbeMode::ForceTcp) => "TCP",
        (Lang::En, ProbeMode::Both) => "Both (UDP + TCP)",
        (Lang::Ru, ProbeMode::Both) => "Оба (UDP + TCP)",
    }
}
