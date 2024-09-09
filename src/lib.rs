//! this is crate for just parse sni in tls client hello buffer,
//! returm endian pos in buffer and sni
//! this crate uses the parser combinator library and DOES NOT PANIC

use log;

/// take sni from buffer and return Option
pub fn take_sni(b: &[u8]) -> Option<(usize, &[u8])> {
    inner_take_sni(b).ok()
} 

/// take sni from buffer and return Result
pub fn inner_take_sni(b: &[u8]) -> Result<(usize, &[u8]), &[u8]> {
    use byteorder::{ByteOrder, BE}; 
    use parcelona::{parser_combinators::{*}, u8::is_any};
    
    const HANDSHAKE_TYPE_CLIENT_HELLO: usize = 1;
    const EXTENSION_TYPE_SNI: usize = 0;
    const NAME_TYPE_HOST_NAME: usize = 0;
    
    let origin_len = b.len(); 
    if origin_len < 10 { return Err(b); }
    let take1 = map(take(seq(is_any,SeqCount::Exact(1))),|x|{x[0] as usize});    
    let take2 = map(take(seq(is_any,SeqCount::Exact(2))),|x|{BE::read_u16(x) as usize});    
    let take3 = map(take(seq(is_any,SeqCount::Exact(3))),|x|{BE::read_u24(x) as usize}); 


    let b = &b[5..]; 
    // Handshake message type.
    let (b, c) = take1.parse(b)?;
    if c!= HANDSHAKE_TYPE_CLIENT_HELLO { return Err(b"Er"); } 
    
    // Handshake message length.
    let (b, c) = take3.parse(b)?;
    log::debug!("1. messag len {:?}", c);
    
    // ProtocolVersion (2 bytes) & random (32 bytes).
    let (b, c) = take(seq(is_any,SeqCount::Exact(34))).parse(b)?;
    
    // Session ID (u8-length vec), cipher suites (u16-length vec), compression methods (u8-length vec).
    let (b, c) = take1.parse(b)?;
    log::debug!("2. session id (need 0) {:?}", c);
    let (b, c) = take(seq(is_any,SeqCount::Exact(c))).parse(b)?;
    let (b, c) = take2.parse(b)?;
    let (b, c) = take(seq(is_any,SeqCount::Exact(c))).parse(b)?;
    let (b, c) = take1.parse(b)?;
    let (b, c) = take(seq(is_any,SeqCount::Exact(c))).parse(b)?;
    
    // Extensions length.
    let (mut b, mut c) = take2.parse(b)?;
    log::debug!("3. Extensions length {:?}", c);
    let (mut ext_type, mut ext_leng) = (0_usize, 0_usize);
    loop {
        // Extension type & length.
        (b, (ext_type, ext_leng)) = pair(take2.clone(), take2.clone()).parse(b)?;
        log::debug!("4. Ext type (0) {:?} len {:?}", ext_type, ext_leng);
        if ext_type != EXTENSION_TYPE_SNI {
            if ext_leng>0 { (b, _) = take(seq(is_any,SeqCount::Exact(ext_leng))).parse(b)?; }
            continue; 
        }
        // ServerNameList length.
        (b, c) = take2.parse(b)?;
        log::debug!("5. ServerNameListmessag len {:?}", c);
        // ServerNameList.
        let (mut name_type, mut name_leng) = (0_usize, 0_usize);
        let mut sni: &[u8];
        loop {
            // NameType & length.
            (b, (name_type, name_leng)) = pair(take1.clone(), take2.clone()).parse(b)?;
            (b, sni) = take(seq(is_any,SeqCount::Exact(name_leng))).parse(b)?;
            if name_type != NAME_TYPE_HOST_NAME { continue; }
            name_leng = origin_len-b.len();
            log::info!("[sni] {:?} sni {:?}", name_leng, String::from_utf8_lossy(sni));
            return Ok((name_leng, sni));
        }  
    }
}

