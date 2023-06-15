


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
        match self._c.next_packet() {
            Ok(mut packet) => {
                let p_dat: &mut [u8] = &mut packet.data.to_owned();
                let data: (&mut [u8], Linktype) = (p_dat, self.get_datalink());
                match MutableIpPacket::try_from(data) {
                    Ok(p) => Ok(p),
                    Err(_) => Err(Error::from("Failed to convert to Mutable")),
                }
            },
            Err(e) => Err(Error::PcapErr(e))
        }
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
        let link = self.get_datalink();
        let bytes: &mut [u8] = self.next_zbalance_packet();
        let data: (&mut [u8], Linktype) = (bytes, link);
        match MutableIpPacket::try_from(data) {
            Ok(p) => Ok(p),
            Err(_) => Err(Error::from("Failed to convert to Mutable")),
        }
    }
    fn get_datalink(&self) -> Linktype {
        Linktype::RAW
    }
}
