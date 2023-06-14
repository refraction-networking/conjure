


use crate::error::Error;
use crate::ip::MutableIpPacket;
use crate::zbalance_ipc::ZbalanceIPCCapture;


use pcap::{self, Activated, Linktype};


pub trait Capture {
    fn next_packet(&mut self) -> Result<MutableIpPacket<'static>, Error>;
    fn get_datalink(&self) -> Linktype;
}


pub struct PcapCapture<A:Activated> {
    _c: pcap::Capture<A>,
}

impl<A: Activated> Capture for PcapCapture<A> {
    fn next_packet(&mut self)-> Result<MutableIpPacket<'static>, Error> {
        todo!("not yet implemented");
        // Err(Error::from("test"))
    }

    fn get_datalink(&self) -> Linktype {
        return self._c.get_datalink()
    }
}

impl<A: Activated> From<pcap::Capture<A>> for PcapCapture<A> {
    fn from(value: pcap::Capture<A>) -> Self {
        return PcapCapture{_c: value}
    }
}


impl Capture for ZbalanceIPCCapture {
    fn next_packet(&mut self)-> Result<MutableIpPacket<'static>, Error> {
        todo!("not yet implemented");
        // Err(Error::from("test"))
    }

    fn get_datalink(&self) -> Linktype {
        Linktype::RAW
    }
}
