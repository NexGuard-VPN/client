pub const FRAME_RELAY: u8 = 0x02;
pub const FRAME_KEEPALIVE: u8 = 0x03;
pub const HEADER_LEN: usize = 5;
pub const KEY_LEN: usize = 32;
pub const MAX_FRAME: usize = 65535;

pub struct Frame<'a> {
    pub kind: u8,
    pub payload: &'a [u8],
}

pub fn encode_relay(out: &mut Vec<u8>, dst: &[u8; KEY_LEN], data: &[u8]) {
    let len = (KEY_LEN + data.len()) as u32;
    out.push(FRAME_RELAY);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(dst);
    out.extend_from_slice(data);
}

pub fn encode_keepalive(out: &mut Vec<u8>) {
    out.push(FRAME_KEEPALIVE);
    out.extend_from_slice(&0u32.to_be_bytes());
}

pub fn next_frame(buf: &[u8]) -> Result<Option<(Frame<'_>, usize)>, ()> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_FRAME {
        return Err(());
    }
    if buf.len() < HEADER_LEN + len {
        return Ok(None);
    }
    Ok(Some((
        Frame {
            kind: buf[0],
            payload: &buf[HEADER_LEN..HEADER_LEN + len],
        },
        HEADER_LEN + len,
    )))
}

pub fn split_addressed(payload: &[u8]) -> Option<([u8; KEY_LEN], &[u8])> {
    if payload.len() <= KEY_LEN {
        return None;
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&payload[..KEY_LEN]);
    Some((key, &payload[KEY_LEN..]))
}
