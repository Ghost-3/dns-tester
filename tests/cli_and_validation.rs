use dns_tester::cli_parse_core::{self, CliCommandSnap, CliIssue};
use dns_tester::primitives::{Lang, ProbeMode};
use dns_tester::validation_core::{
    self, DomainIssue, TargetIssue, TimeoutIssue, ValidationIssue, ValidationSnap,
};

fn args(slice: &[&str]) -> Box<[String]> {
    slice
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

#[test]
fn cli_defaults_to_auto_and_english() {
    let parsed = cli_parse_core::parse(&args(&["8.8.8.8"]));
    assert!(matches!(parsed.lang, Lang::En));

    let CliCommandSnap::Run {
        mode,
        raw_ip,
        raw_domain,
        raw_timeout_ms,
    } = parsed.command
    else {
        panic!("Expected CliCommandSnap::Run");
    };

    assert!(matches!(mode, ProbeMode::Auto));
    assert_eq!(raw_ip, "8.8.8.8");
    assert!(raw_domain.is_none());
    assert!(raw_timeout_ms.is_none());
}

#[test]
fn cli_detects_russian_lang_even_after_help_or_bad_flag() {
    // --ru стоит в самом конце после --help, но однопроходный парсер должен его увидеть
    let parsed = cli_parse_core::parse(&args(&["--help", "--ru"]));
    assert!(matches!(parsed.lang, Lang::Ru));
    assert!(matches!(
        parsed.command,
        CliCommandSnap::Aborted(CliIssue::HelpRequested)
    ));

    // --ru после неизвестного флага
    let parsed_err = cli_parse_core::parse(&args(&["--unknown", "--ru"]));
    assert!(matches!(parsed_err.lang, Lang::Ru));
    assert!(matches!(
        parsed_err.command,
        CliCommandSnap::Aborted(CliIssue::UnknownFlag(_))
    ));
}

#[test]
fn cli_rejects_conflicting_modes() {
    let parsed = cli_parse_core::parse(&args(&["8.8.8.8", "--udp", "--tcp"]));
    assert!(matches!(
        parsed.command,
        CliCommandSnap::Aborted(CliIssue::ConflictingModes)
    ));
}

#[test]
fn validation_applies_defaults_and_parses_custom_port() {
    // 1. Голый IP без домена и таймаута -> порт 53, example.com., 2000 мс
    let ValidationSnap::Valid {
        target,
        domain,
        timeout,
    } = validation_core::validate("1.1.1.1", None, None)
    else {
        panic!("Expected Valid");
    };

    assert_eq!(target.socket_addr().to_string(), "1.1.1.1:53");
    assert_eq!(domain.as_name().to_ascii(), "example.com.");
    assert_eq!(timeout.as_millis(), 2000);

    // 2. Кастомный порт и параметры
    let ValidationSnap::Valid { target, .. } =
        validation_core::validate("127.0.0.1:5353", Some("google.com"), Some("500"))
    else {
        panic!("Expected Valid with custom port");
    };

    assert_eq!(target.socket_addr().to_string(), "127.0.0.1:5353");
}

#[test]
fn validation_catches_invalid_target_domain_and_timeout() {
    assert!(matches!(
        validation_core::validate("999.999.999.999", None, None),
        ValidationSnap::Invalid(ValidationIssue::Target(TargetIssue::InvalidAddress(_)))
    ));

    assert!(matches!(
        validation_core::validate("127.0.0.1:0", None, None),
        ValidationSnap::Invalid(ValidationIssue::Target(TargetIssue::ZeroPort))
    ));

    assert!(matches!(
        validation_core::validate("8.8.8.8", Some("   "), None),
        ValidationSnap::Invalid(ValidationIssue::Domain(DomainIssue::Empty))
    ));

    assert!(matches!(
        validation_core::validate("8.8.8.8", None, Some("0")),
        ValidationSnap::Invalid(ValidationIssue::Timeout(TimeoutIssue::Zero))
    ));

    assert!(matches!(
        validation_core::validate("8.8.8.8", None, Some("999999")),
        ValidationSnap::Invalid(ValidationIssue::Timeout(TimeoutIssue::TooLarge { .. }))
    ));
}
