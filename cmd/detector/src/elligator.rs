use std::panic;

use c_api;

use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::{Aes128Gcm, KeyInit};
use protobuf::Message;
use signalling::ClientToStation;
use std::error::Error;
use util::{HKDFKeys, FSP};

const REPRESENTATIVE_AND_FSP_LEN: usize = 54;
//  elligator2.h
//  Assuming curve25519; prime p = 2^255-19; curve y^2 = x^3 + A*x^2 + x;
//  A = 486662
//  Elliptic curve points represented as bytes. Each coordinate is 32 bytes.
//  On curve25519, always take canonical y in range 0,..,(p-1)/2.
//  We can ignore y-coord.

// Extracts 3 stego'd bytes in_bufto 'out_buf', from the 4 bytes of AES
// ciphertext at 'in_buf'.
fn extract_stego_bytes(in_buf: &[u8], out_buf: &mut [u8]) {
    assert!(in_buf.len() == 4);
    assert!(out_buf.len() == 3);

    let x = ((in_buf[0] & 0x3f) as u32) * (64 * 64 * 64)
        + ((in_buf[1] & 0x3f) as u32) * (64 * 64)
        + ((in_buf[2] & 0x3f) as u32) * (64)
        + ((in_buf[3] & 0x3f) as u32);

    out_buf[0] = ((x >> 16) & 0xff) as u8;
    out_buf[1] = ((x >> 8) & 0xff) as u8;
    out_buf[2] = ((x) & 0xff) as u8;
}

type PayloadElements = ([u8; 32], [u8; FSP::LENGTH], ClientToStation);

// Returns either (Shared Secret, Fixed Size Payload, Variable Size Payload) or Box<Error>
//      Boxed error becuase size of return isn't known at compile time
pub fn extract_payloads(
    secret_key: &[u8],
    tls_record: &[u8],
) -> Result<PayloadElements, Box<dyn Error>> {
    if tls_record.len() < 112
    // (conservatively) smaller than minimum request
    {
        let err: Box<dyn Error> = From::from("small tls record".to_string());
        return Err(err);
    }

    // This fn indexes a lot of slices with computed offsets; panics possible!
    let result = panic::catch_unwind(|| {
        // TLS record: 1 byte of 'content type', 2 of 'version', 2 of 'length',
        //               and then [length] bytes of 'payload'
        //======================================================================
        //let content_type = tls_record[0];
        //let tls_version = u8u8_to_u16(tls_record[1], tls_record[2]);

        let tls_payload = &tls_record[5..tls_record.len()];
        //======================================================================
        // Starting from 92 byte from the end of the TLS payload extract
        // stego'd data from each block of 4 bytes (if the payload length isn't
        // a multiple of 4, just ignore the tail). Continue until we have run
        // out of input data, or room in the output buffer.
        //     See Registration-Tagging-and-Signaling on the wiki for an explanation
        //  of the 92 byte magic number here.
        let mut stego_repr_and_fsp: [u8; REPRESENTATIVE_AND_FSP_LEN] =
            [0; REPRESENTATIVE_AND_FSP_LEN];
        let mut in_offset: usize = tls_payload.len() - 92;
        let mut out_offset: usize = 0;
        while in_offset < (tls_payload.len() - 3) && out_offset < (REPRESENTATIVE_AND_FSP_LEN - 2) {
            extract_stego_bytes(
                &tls_payload[in_offset..in_offset + 4],
                &mut stego_repr_and_fsp[out_offset..out_offset + 3],
            );
            in_offset += 4;
            out_offset += 3;
        }

        // let b: Vec<u8> = stego_repr_and_fsp.iter().cloned().collect();
        // debug!("repr: {:}", hex::encode(b));

        // client should randomize first (and second) bit, here we set it back to 0
        stego_repr_and_fsp[31] &= 0x3f;

        let mut shared_secret: [u8; 32] = [0; 32];
        c_api::c_get_shared_secret_from_tag(
            secret_key,
            &mut stego_repr_and_fsp,
            &mut shared_secret,
        );

        let keys = match HKDFKeys::new(shared_secret.as_ref()) {
            Ok(keys) => keys,
            Err(e) => {
                let err: Box<dyn Error> = From::from(e.to_string());
                return Err(err);
            }
        };

        // Initialize FSP AES cipher
        let key = GenericArray::from_slice(&keys.fsp_key);
        let cipher = Aes128Gcm::new(key);
        let nonce = GenericArray::from_slice(&keys.fsp_iv);

        // Decrypt the Fixed size payload (6 bytes + 16 bytes GCM tag)
        let fixed_size_payload_bytes = match cipher.decrypt(nonce, &stego_repr_and_fsp[32..54]) {
            Ok(fspb) => fspb,
            Err(err) => {
                let err: Box<dyn Error> = From::from(format!("fsp_aes_gcm.decrypt failed: {err}"));
                return Err(err);
            }
        };

        let fixed_size_payload = FSP::from_vec(fixed_size_payload_bytes.to_vec())?;

        let vsp_size = fixed_size_payload.vsp_size; // includes aes gcm tag
        if vsp_size <= 16 {
            let err: Box<dyn Error> =
                From::from(format!("Variable Stego Payload Size {vsp_size} too small"));
            return Err(err);
            //  return Ok((keys, fixed_size_payload, vec![]));
        }
        if vsp_size % 3 != 0 {
            let err: Box<dyn Error> = From::from(format!(
                "Variable Stego Payload Size {vsp_size} non-divisible by 3"
            ));
            return Err(err);
        }
        let vsp_stego_size = vsp_size / 3 * 4;
        let mut encrypted_variable_size_payload = vec![0; vsp_size as usize];
        if (tls_payload.len() as i64) - (92_i64) - (vsp_stego_size as i64) < 0 {
            let err: Box<dyn Error> = From::from(format!(
                "Stego Payload Size {} does not fit into TLS record of size {}",
                vsp_size,
                tls_payload.len()
            ));
            return Err(err);
        }
        in_offset = tls_payload.len() - 92 - vsp_stego_size as usize;
        out_offset = 0;
        while in_offset < (tls_payload.len() - 3) && out_offset < (vsp_size - 2) as usize {
            extract_stego_bytes(
                &tls_payload[in_offset..in_offset + 4],
                &mut encrypted_variable_size_payload[out_offset..out_offset + 3],
            );
            in_offset += 4;
            out_offset += 3;
        }

        // Initialize VSP AES cipher
        let key = GenericArray::from_slice(&keys.vsp_key);
        let cipher = Aes128Gcm::new(key);
        let nonce = GenericArray::from_slice(&keys.vsp_iv);

        // Decrypt the Variable size payload using the size specified in the fixed sized payload
        let variable_size_payload = match cipher.decrypt(
            nonce,
            &encrypted_variable_size_payload[0..vsp_size as usize],
        ) {
            Ok(vsp) => vsp,
            Err(err) => {
                let err: Box<dyn Error> = From::from(format!("failed to decrypt vsp: {err}"));
                return Err(err);
            }
        };

        let c2s: ClientToStation = match Message::parse_from_bytes(&variable_size_payload) {
            Ok(c2s) => c2s,
            Err(err) => return Err(Box::new(err)),
        };
        Ok((shared_secret, fixed_size_payload.to_bytes(), c2s))
    });
    match result {
        Ok(res) => res,
        Err(e) => {
            let err: Box<dyn Error> = From::from(format!("{e:?}"));
            Err(err)
        }
    }
} // end extract_payloads_new

/* Uses a function from an external library; run separately from other tests.
#[cfg(test)]
mod tests {
use elligator;
#[test]
fn elligator_extracts_telex_tag()
{
    let secret_key : [u8; 32] = [
    224, 192, 103, 26, 96, 135, 130, 174, 250, 208, 30, 113, 46, 128, 127, 111,
    215, 199, 5, 141, 38, 124, 34, 127, 102, 142, 245, 81, 49, 70, 119, 119];

    let tls_record : [u8; 325] = [23, 3, 3, 1, 64, 22, 160, 106, 230, 9, 73,
    117, 77, 155, 195, 52, 186, 101, 164, 19, 44, 80, 219, 142, 191, 38, 219,
    106, 55, 73, 194, 87, 48, 171, 18, 226, 115, 69, 64, 93, 64, 149, 98, 4,
    200, 150, 164, 213, 150, 8, 196, 75, 144, 134, 147, 8, 114, 48, 14, 213,
229, 117, 13, 49, 191, 104, 83, 80, 140, 68, 143, 184, 11, 152, 70, 140, 139,
215, 32, 14, 192, 4, 188, 36, 30, 173, 32, 4, 32, 187, 47, 129, 61, 70, 228, 77,
68, 145, 133, 72, 252, 96, 168, 103, 44, 148, 97, 207, 145, 166, 49, 228, 140,
134, 94, 231, 198, 251, 101, 119, 196, 149, 77, 186, 153, 34, 252, 110, 178,
151, 131, 167, 171, 238, 79, 57, 242, 23, 199, 190, 89, 106, 244, 215, 152, 120,
1, 208, 251, 204, 213, 148, 98, 170, 41, 103, 102, 15, 200, 222, 244, 60, 43,
159, 171, 71, 155, 218, 157, 218, 10, 141, 243, 2, 11, 199, 181, 166, 237, 106,
125, 221, 185, 25, 151, 203, 147, 150, 252, 31, 205, 232, 100, 127, 48, 143,
160, 186, 220, 133, 163, 193, 221, 115, 216, 91, 172, 131, 24, 58, 74, 109, 222,
123, 204, 144, 182, 185, 213, 107, 84, 135, 56, 137, 78, 134, 60, 190, 65, 13,
233, 188, 216, 1, 71, 172, 154, 171, 148, 182, 249, 155, 114, 42, 210, 86, 88,
95, 127, 179, 22, 25, 137, 231, 196, 185, 225, 233, 14, 87, 95, 159, 139, 205,
99, 1, 96, 225, 154, 157, 184, 10, 73, 158, 211, 235, 211, 104, 75, 68, 85, 253,
33, 19, 71, 127, 63, 223, 124, 186, 246, 62, 164, 223, 111, 207, 152, 161, 18,
71, 191, 103, 204, 75, 34, 108, 147, 10, 242, 64, 245, 135, 29, 49, 129, 244,
62, 36, 2, 230, 91, 129, 205, 98, 252];

    let expected : [u8; 136] = [83, 80, 84, 69, 76, 69, 88, 48, 73, 119, 10,
208, 64, 218, 217, 76, 217, 166, 140, 244, 192, 78, 192, 30, 158, 239, 137, 71,
114, 81, 83, 224, 110, 188, 246, 146, 0, 187, 198, 116, 99, 106, 231, 176, 28,
178, 81, 235, 13, 53, 50, 46, 141, 30, 7, 161, 87, 113, 204, 12, 97, 66, 253,
45, 126, 235, 128, 248, 93, 203, 118, 136, 165, 253, 124, 55, 180, 23, 63, 52,
233, 52, 183, 196, 194, 40, 106, 21, 174, 245, 121, 58, 145, 158, 89, 49, 51,
118, 118, 188, 68, 91, 218, 164, 230, 198, 102, 213, 122, 255, 119, 78, 79, 17,
209, 84, 235, 44, 137, 36, 113, 230, 141, 192, 155, 130, 33, 180, 217, 98, 198,
200, 157, 165, 25, 21];

    let out = elligator::extract_telex_tag(&secret_key, &tls_record);
    assert_eq!(expected.to_vec(), out.to_vec());
}
} // mod tests
*/
