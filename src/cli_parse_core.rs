//! Чистое расчётное ядро: однопроходный синтаксический разбор флагов и позиционных аргументов CLI.

use crate::primitives::{Lang, ProbeMode};

const DEFAULT_LANG: Lang = Lang::En;
const DEFAULT_MODE: ProbeMode = ProbeMode::Auto;

pub struct ParsedCli {
    pub lang: Lang,
    pub command: CliCommandSnap,
}

pub enum CliCommandSnap {
    Run {
        mode: ProbeMode,
        raw_ip: String,
        raw_domain: Option<String>,
        raw_timeout_ms: Option<String>,
    },
    Aborted(CliIssue),
}

pub enum CliIssue {
    HelpRequested,
    MissingArguments,
    UnknownFlag(String),
    ConflictingModes,
    ConflictingLangs,
    TooManyArguments(String),
}

enum Token<'a> {
    Help,
    Lang(Lang),
    Mode(ProbeMode),
    UnknownFlag(&'a str),
    Positional(&'a str),
}

/// Просматривает все токены до конца среза без раннего выхода в цикле,
/// чтобы флаг языка (`--ru` / `--en`) учитывался даже после `--help` или ошибочного флага.
pub fn parse(raw_args: &[String]) -> ParsedCli {
    let mut lang: Option<Lang> = None;
    let mut mode: Option<ProbeMode> = None;
    let mut help_requested = false;
    let mut first_issue: Option<CliIssue> = None;

    let mut raw_ip: Option<String> = None;
    let mut raw_domain: Option<String> = None;
    let mut raw_timeout_ms: Option<String> = None;

    for arg in raw_args {
        match classify_token(arg) {
            Token::Help => {
                help_requested = true;
            }
            Token::Lang(parsed_lang) => {
                if let Some(existing) = lang {
                    if existing != parsed_lang && first_issue.is_none() {
                        first_issue = Some(CliIssue::ConflictingLangs);
                    }
                } else {
                    lang = Some(parsed_lang);
                }
            }
            Token::Mode(parsed_mode) => {
                if let Some(existing) = mode {
                    if existing != parsed_mode && first_issue.is_none() {
                        first_issue = Some(CliIssue::ConflictingModes);
                    }
                } else {
                    mode = Some(parsed_mode);
                }
            }
            Token::UnknownFlag(flag) => {
                if first_issue.is_none() {
                    first_issue = Some(CliIssue::UnknownFlag(flag.to_string()));
                }
            }
            Token::Positional(val) => {
                if raw_ip.is_none() {
                    raw_ip = Some(val.to_string());
                } else if raw_domain.is_none() {
                    raw_domain = Some(val.to_string());
                } else if raw_timeout_ms.is_none() {
                    raw_timeout_ms = Some(val.to_string());
                } else if first_issue.is_none() {
                    first_issue = Some(CliIssue::TooManyArguments(val.to_string()));
                }
            }
        }
    }

    let resolved_lang = lang.unwrap_or(DEFAULT_LANG);

    if help_requested {
        return ParsedCli {
            lang: resolved_lang,
            command: CliCommandSnap::Aborted(CliIssue::HelpRequested),
        };
    }

    if let Some(issue) = first_issue {
        return ParsedCli {
            lang: resolved_lang,
            command: CliCommandSnap::Aborted(issue),
        };
    }

    let Some(raw_ip) = raw_ip else {
        return ParsedCli {
            lang: resolved_lang,
            command: CliCommandSnap::Aborted(CliIssue::MissingArguments),
        };
    };

    ParsedCli {
        lang: resolved_lang,
        command: CliCommandSnap::Run {
            mode: mode.unwrap_or(DEFAULT_MODE),
            raw_ip,
            raw_domain,
            raw_timeout_ms,
        },
    }
}

/// Граница с произвольным пользовательским вводом: переводит сырую строку в конечный Token.
fn classify_token(arg: &str) -> Token<'_> {
    match arg {
        "-h" | "--help" => Token::Help,
        "--ru" => Token::Lang(Lang::Ru),
        "--en" => Token::Lang(Lang::En),
        "--auto" => Token::Mode(ProbeMode::Auto),
        "--udp" => Token::Mode(ProbeMode::ForceUdp),
        "--tcp" => Token::Mode(ProbeMode::ForceTcp),
        "--both" => Token::Mode(ProbeMode::Both),
        _ if arg.starts_with('-') => Token::UnknownFlag(arg),
        _ => Token::Positional(arg),
    }
}
