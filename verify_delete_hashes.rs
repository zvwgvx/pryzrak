fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ (s[i] as u32);
        i += 1;
    }
    hash
}

fn main() {
    let apis = vec![
        "SetFileInformationByHandle",
        "GetModuleFileNameW",
    ];

    for api in apis {
        println!("{}: 0x{:X}", api, djb2(api.as_bytes()));
    }
}
