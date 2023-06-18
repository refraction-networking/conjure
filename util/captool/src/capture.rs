use crate::error::Error;
use crate::zbalance_ipc::ZbalanceIPCCapture;
use std::fs;

use pcap::{self, Activated, Device, Linktype, Packet, PacketHeader};

pub trait Capture {
    fn next_packet(&mut self) -> Result<Packet<'_>, Error>;
    fn get_datalink(&self) -> Linktype;
}

pub struct PcapCapture<A: Activated> {
    _c: pcap::Capture<A>,
}

impl<A: Activated> Capture for PcapCapture<A> {
    fn next_packet(&mut self) -> Result<Packet<'_>, Error> {
        Ok(self._c.next_packet()?)
    }

    fn get_datalink(&self) -> Linktype {
        return self._c.get_datalink();
    }
}

impl<A: Activated> From<pcap::Capture<A>> for PcapCapture<A> {
    fn from(value: pcap::Capture<A>) -> Self {
        return PcapCapture { _c: value };
    }
}

impl Capture for ZbalanceIPCCapture {
    fn next_packet(&mut self) -> Result<Packet<'_>, Error> {
        let ts = self.time_since_start();

        // take should give us ownership of the bytes without performing a copy.
        let bytes = std::mem::take(&mut self.next_zbalance_packet());

        // We create a Box<PacketHeader> named packet_header on the heap. We then pass a reference to
        // the PacketHeader by performing an as_ref() on the Box and casting it to a raw pointer
        // using *const PacketHeader. Since the PacketHeader is owned by the Box, its memory is
        // guaranteed to be valid. We dereference the raw pointer to obtain the reference needed for
        // the Packet struct.
        let packet_header = Box::new(PacketHeader {
            ts,
            caplen: bytes.len() as u32,
            len: bytes.len() as u32,
        });

        // This `unsafe` code bypasses Rust's safety guarantees, meaning that we must ensure that
        // the lifetime of the PacketHeader is valid and that the data remains accessible during the
        // entire lifetime of the Packet ourselves. There is currently no reason why it would not be
        let packet =
            unsafe { Packet::new(&*(packet_header.as_ref() as *const PacketHeader), bytes) };
        Ok(packet)
    }

    fn get_datalink(&self) -> Linktype {
        Linktype::ETHERNET
    }
}

pub fn from_pcap_dir(pcap_dir: String) -> Result<Vec<Box<dyn Capture>>, Error> {
    let mut captures: Vec<Box<dyn Capture>> = vec![];

    // refresh the path list and launch jobs
    let paths = fs::read_dir(pcap_dir).unwrap();
    for path in paths {
        match path {
            Ok(p) => {
                let cap = pcap::Capture::from_file(p.path()).unwrap();
                let capture = PcapCapture::from(cap);
                captures.push(Box::new(capture) as Box<dyn Capture>);
            }
            Err(e) => println!("path error: {e}"),
        }
    }
    Ok(captures)
}

pub fn from_interface_list(interfaces: String) -> Result<Vec<Box<dyn Capture>>, Error> {
    let mut captures: Vec<Box<dyn Capture>> = vec![];

    for iface in interfaces.split(',') {
        match Device::list()
            .unwrap()
            .into_iter()
            .find(|d| d.name == iface)
        {
            Some(dev) => {
                let cap = pcap::Capture::from_device(dev)
                    .unwrap()
                    .immediate_mode(true) // enable immediate mode
                    .open()
                    .unwrap();
                let capture = PcapCapture::from(cap);
                captures.push(Box::new(capture) as Box<dyn Capture>);
            }
            None => println!("Couldn't find interface '{iface}'"),
        }
    }
    Ok(captures)
}

pub fn from_zbalance_queues(
    cluster_id: i32,
    queue_count: i32,
    queue_offset: i32,
) -> Result<Vec<Box<dyn Capture>>, Error> {
    let mut captures: Vec<Box<dyn Capture>> = vec![];

    for queue_id in 0..queue_count {
        let zb_ipc_cap = ZbalanceIPCCapture::new(cluster_id, queue_id + queue_offset);
        captures.push(Box::new(zb_ipc_cap) as Box<dyn Capture>);
    }
    Ok(captures)
}
