//! Граничный узел среды: генерация случайного идентификатора DNS-запроса.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

/// Биографический примитив ID запроса: рождается исключительно в `RandomNode`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QueryId(u16);

impl QueryId {
    pub fn as_u16(self) -> u16 {
        self.0
    }
}

pub struct RandomNode;

impl RandomNode {
    pub fn next_query_id(&self) -> QueryId {
        let random_u64 = RandomState::new().build_hasher().finish();
        QueryId(random_u64 as u16)
    }
}
