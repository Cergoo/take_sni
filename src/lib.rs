//! this is crate for just parse sni in tls client hello buffer,
//! returm endian pos in buffer and sni
//! this crate uses the parser combinator library and DOES NOT PANIC

use log;

/// take sni from buffer and return Option
pub fn take_sni(b: &[u8]) -> Option<(usize, &[u8])> {
    inner_take_sni(b).ok()
}

// take just coordinat sni in buffer
pub fn take_sni_point(b: &[u8]) -> Option<(usize, usize)> {
    inner_take_sni(b).ok().map(|r|(r.0-r.1.len(), r.0))
}

/// take sni from buffer and return Result
pub fn inner_take_sni(b: &[u8]) -> Result<(usize, &[u8]), &[u8]> {
    use parcelona::u8ext::{*};
    
    const HANDSHAKE_TYPE_CLIENT_HELLO: usize = 1;
    const EXTENSION_TYPE_SNI: usize = 0;
    const NAME_TYPE_HOST_NAME: usize = 0;
    
    let origin_len = b.len(); 
    if origin_len < 10 { return Err(b); }

    let b = &b[5..]; 
    // Handshake message type.
    let (b, c) = take_len_be_u8(b)?;
    if c!= HANDSHAKE_TYPE_CLIENT_HELLO { return Err(b"Er"); } 
    
    // Handshake message length.
    let (b, c) = take_len_be_u24(b)?;
    log::debug!("1. messag len {:?}", c);
    
    // ProtocolVersion (2 bytes) & random (32 bytes).
    let (b, _) = take_record(b,34)?;
    
    // Session ID (u8-length vec), cipher suites (u16-length vec), compression methods (u8-length vec).
    let (b, _) = take_record_be_u8(b)?;
    let (b, _) = take_record_be_u16(b)?;
    let (b, _) = take_record_be_u8(b)?;

    // Extensions length.
    let (mut b, mut c) = take_len_be_u16(b)?;
    let mut ext_type: usize;
    let mut ext_leng: usize;
    log::debug!("3. Extensions length {:?}", c);
    loop {
        // Extension type & length.
        (b, ext_type) = take_len_be_u16(b)?;
        (b, ext_leng) = take_len_be_u16(b)?;

        log::debug!("4. Ext type (0) {:?} len {:?}", ext_type, ext_leng);
        if ext_type != EXTENSION_TYPE_SNI {
            if ext_leng>0 { (b, _) = take_record(b, ext_leng)?; }
            continue; 
        }
        // ServerNameList length.
        (b, c) = take_len_be_u16(b)?;
        log::debug!("5. ServerNameListmessag len {:?}", c);
        // ServerNameList.
        let mut sni: &[u8];
        let mut name_type: usize;
        let mut name_leng: usize;
        loop {
            // NameType & length.
            (b, name_type) = take_len_be_u8(b)?;
            (b, name_leng) = take_len_be_u16(b)?;
            (b, sni) = take_record(b, name_leng)?;
            if name_type != NAME_TYPE_HOST_NAME { continue; }
            let sni_point: usize = origin_len-b.len();
            log::info!("[sni] {:?} sni {:?}", sni_point, String::from_utf8_lossy(sni));
            return Ok((sni_point, sni));
        }  
    }
}

