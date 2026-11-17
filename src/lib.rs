//! Эталонная реализация Изолирующей фрактальной архитектуры (ИФА): диагностический DNS-тестер.

pub mod cli_node;
pub mod cli_parse_core;
pub mod dns_core;
pub mod format_core;
pub mod primitives;
pub mod probe_hub;
pub mod random_node;
pub mod tcp_node;
pub mod udp_node;
pub mod validation_core;
