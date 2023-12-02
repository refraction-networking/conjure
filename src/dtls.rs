// dtls_content_aware_unpack_datagram is the same as webrtc_dtls::record_layer::unpack_datagram
// but considers the presence of a connection identifier if the record is of content type
// tls12_cid.
fn dtls_content_aware_unpack_datagram(
    buf: &[u8],
    cid_length: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut out = Vec::new();
    let mut offset = 0;

    while buf.len() != offset {
        let mut header_size = FIXED_HEADER_SIZE;
        let mut len_idx = FIXED_HEADER_LEN_IDX;

        if protocol::content_type(buf[offset]) == protocol::ContentType::ConnectionID {
            header_size += cid_length;
            len_idx += cid_length;
        }

        if buf.len() - offset <= header_size {
            return Err(Error::ErrInvalidPacketLength);
        }

        let pkt_len = header_size
            + (((buf[offset + len_idx] as usize) << 8) | buf[offset + len_idx + 1] as usize);

        if offset + pkt_len > buf.len() {
            return Err(Error::ErrInvalidPacketLength);
        }

        out.push(buf[offset..offset + pkt_len].to_vec());
        offset += pkt_len;
    }

    Ok(out)
}
