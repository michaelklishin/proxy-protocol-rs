#![no_main]
use libfuzzer_sys::fuzz_target;
use proxy_protocol_rs::parse;

fuzz_target!(|data: &[u8]| {
    let _ = parse(data);
});
