use crate::ip::PacketType;

use std::fmt::{self, Display};
use std::hash::Hash;

pub trait Limit: Send + Sync {
    fn reset(&mut self);

    fn check_flag(&self) -> bool;

    fn count_or_drop(
        &mut self,
        key: Hashable,
        afi: String,
        t: PacketType,
    ) -> Result<(), LimitError>;

    fn count_or_drop_many(
        &mut self,
        keys: Vec<Hashable>,
        afi: String,
        t: PacketType,
    ) -> Result<Hashable, LimitError>;
}

impl From<&String> for Hashable {
    fn from(item: &String) -> Self {
        Hashable::Str(item.clone())
    }
}

impl From<String> for Hashable {
    fn from(item: String) -> Self {
        Hashable::Str(item)
    }
}

impl From<&str> for Hashable {
    fn from(item: &str) -> Self {
        Hashable::Str(String::from(item))
    }
}

impl From<i32> for Hashable {
    fn from(item: i32) -> Self {
        Hashable::U32(item as u32)
    }
}

impl From<&&str> for Hashable {
    fn from(item: &&str) -> Self {
        Hashable::Str(String::from(*item))
    }
}

impl From<&u32> for Hashable {
    fn from(item: &u32) -> Self {
        Hashable::U32(*item)
    }
}

impl From<u32> for Hashable {
    fn from(item: u32) -> Self {
        Hashable::U32(item)
    }
}

impl From<()> for Hashable {
    fn from(_: ()) -> Self {
        Hashable::Z
    }
}

#[derive(Debug, PartialEq)]
pub enum LimitError {
    FullPPF,
    Full(Hashable),
    NoRelevantKeys,
    UnknownFlow,
    Flag,
}

impl std::error::Error for LimitError {}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LimitError::Full(h) => write!(f, "{h} full"),
            LimitError::FullPPF => write!(f, "flow full"),
            LimitError::NoRelevantKeys => write!(f, "non-tracked key"),
            LimitError::UnknownFlow => write!(f, "non-syn tcp from untracked flow"),
            LimitError::Flag => write!(f, "flag triggered"),
        }
    }
}

#[derive(Debug, PartialEq, Hash, Eq, Clone)]
pub enum Hashable {
    Str(String),
    U32(u32),
    Z, // when we don't need a type
}
impl Display for Hashable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Hashable::Str(s) => write!(f, "{}", s),
            Hashable::U32(s) => write!(f, "{}", s),
            Hashable::Z => write!(f, "count"),
        }
    }
}

#[allow(dead_code)]
impl Hashable {
    fn from<T>(keys: Vec<T>) -> Vec<Self>
    where
        T: Into<Self> + Clone,
    {
        keys.into_iter().map(|k| k.into()).collect()
    }
}
