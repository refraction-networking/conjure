use crate::limit::LimitError;
use crate::packet_handler::PacketError;

use pcap;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    LimitErr(LimitError),
    PacketErr(PacketError),
    OtherErr(Box<dyn std::error::Error>),
    PcapErr(pcap::Error),
}

impl std::error::Error for Error {}

impl From<LimitError> for Error {
    fn from(value: LimitError) -> Self {
        Error::LimitErr(value)
    }
}

impl From<PacketError> for Error {
    fn from(value: PacketError) -> Self {
        Error::PacketErr(value)
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(value: Box<dyn std::error::Error>) -> Self {
        Error::OtherErr(value)
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Error::OtherErr(value.into())
    }
}

impl From<pcap::Error> for Error {
    fn from(value: pcap::Error) -> Self {
        Error::PcapErr(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::PacketErr(e) => write!(f, "{e}"),
            Error::LimitErr(e) => write!(f, "{e}"),
            Error::OtherErr(e) => write!(f, "{e}"),
            e => write!(f, "{e}"),
        }
    }
}
