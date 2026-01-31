use std::fs::File;
use std::io::{Read, Write};
use std::env;
use flate2::write::DeflateEncoder;
use flate2::Compression;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: steg_maker <input_exe> <output_png>");
        return;
    }

    let input_path = &args[1];
    let output_path = &args[2];

    let mut input_data = Vec::new();
    let mut file = File::open(input_path).expect("Cannot open input file");
    file.read_to_end(&mut input_data).expect("Cannot read input file");

    // STEP 1: Compress with deflate to reduce entropy
    let compressed = {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&input_data).expect("Compression failed");
        encoder.finish().expect("Compression finish failed")
    };
    
    println!("Compressed: {} -> {} bytes ({:.1}% ratio)", 
        input_data.len(), compressed.len(), 
        (compressed.len() as f64 / input_data.len() as f64) * 100.0);

    // STEP 2: XOR with key (simple obfuscation layer)
    let xor_key: u8 = 0x55;
    let obfuscated: Vec<u8> = compressed.iter().map(|b| b ^ xor_key).collect();

    // STEP 3: Add magic header to identify compressed format
    // Header: "PZLB" + 4 bytes original size + 4 bytes compressed size
    let mut payload = Vec::new();
    payload.extend_from_slice(b"PZLB"); // Magic
    payload.extend_from_slice(&(input_data.len() as u32).to_le_bytes()); // Original size
    payload.extend_from_slice(&(obfuscated.len() as u32).to_le_bytes()); // Compressed size
    payload.extend_from_slice(&obfuscated);

    // Build PNG
    let mut png_data = Vec::new();

    // 1. PNG Signature
    png_data.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]);

    // 2. IHDR Chunk
    let width = 1024u32;
    let height = ((payload.len() as u32) / 1024) + 1;
    
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&width.to_be_bytes());
    ihdr_data.extend_from_slice(&height.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB

    write_chunk(&mut png_data, b"IHDR", &ihdr_data);

    // 3. biLn chunks (64KB each)
    for chunk in payload.chunks(65536) {
        write_chunk(&mut png_data, b"biLn", chunk);
    }

    // 4. IEND
    write_chunk(&mut png_data, b"IEND", &[]);

    let mut out_file = File::create(output_path).expect("Cannot create output file");
    out_file.write_all(&png_data).expect("Cannot write output file");

    println!("PNG Stego created: {} -> {} ({} bytes)", input_path, output_path, png_data.len());
}

fn write_chunk(vec: &mut Vec<u8>, type_code: &[u8; 4], data: &[u8]) {
    vec.extend_from_slice(&(data.len() as u32).to_be_bytes()); // Length
    vec.extend_from_slice(type_code); // Type
    vec.extend_from_slice(data); // Data
    vec.extend_from_slice(&0u32.to_be_bytes()); // CRC (dummy)
}

