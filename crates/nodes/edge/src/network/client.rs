use smol::net::TcpStream;
use futures_lite::io::{AsyncWriteExt, AsyncReadExt};
use std::error::Error;
use std::time::Duration;
use log::{info, warn, debug, error};
use rand::RngCore;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use async_channel::{Sender, Receiver};

use protocol::uplink::MqttPacket;

const AUTH_TOPIC: &str = "dev/sys/log";

pub struct PolyMqttClient {
    iot_ip: String,
    iot_port: u16,
    master_key: Key, 
}

impl PolyMqttClient {
    pub fn new(iot_ip: &str, iot_port: u16, key_bytes: &[u8; 32]) -> Self {
        Self {
            iot_ip: iot_ip.to_string(),
            iot_port,
            master_key: *Key::from_slice(key_bytes),
        }
    }

    pub async fn send_secure_payload(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let addr = format!("{}:{}", self.iot_ip, self.iot_port);
        let mut stream = TcpStream::connect(&addr).await?;
        self.write_packet(&mut stream, data).await?;
        Ok(())
    }

    pub async fn start_persistent_loop(
        &self, 
        msg_rx: Receiver<Vec<u8>>,
        cmd_tx: Sender<Vec<u8>>
    ) {
        let addr = format!("{}:{}", self.iot_ip, self.iot_port);
        info!("[PolyClient] Starting Persistent Loop for {}", addr);

        loop { // reconnect loop
            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    info!("[PolyClient] Connected to Cloud.");
                    
                    // Split stream into Reader and Writer
                    let (mut reader, mut writer) = futures_lite::io::split(stream);
                    
                    // Reader Task: Reads frames and sends to cmd_tx
                    // This task owns the reader and runs until error
                    let reader_logic = async {
                        loop {
                            match self.read_frame(&mut reader).await {
                                Ok(payload) => {
                                    debug!("[PolyClient] Recv {} bytes from Cloud", payload.len());
                                    if cmd_tx.send(payload).await.is_err() {
                                        error!("[PolyClient] Cmd channel closed");
                                        return;
                                    }
                                }
                                Err(e) => {
                                    error!("[PolyClient] Read Error: {}", e);
                                    return;
                                }
                            }
                        }
                    };

                    // Writer Task: Reads from msg_rx and writes frames
                    // Also handles heartbeats if needed (though msg_rx usually comes from a heartbeat loop)
                    let writer_logic = async {
                        while let Ok(msg) = msg_rx.recv().await {
                            if let Err(e) = self.write_frame(&mut writer, &msg).await {
                                error!("[PolyClient] Write Error: {}", e);
                                return;
                            }
                        }
                    };

                    // Race them: If either dies (connection error), we reconnect
                    futures_lite::future::race(reader_logic, writer_logic).await;
                    
                    warn!("[PolyClient] Connection Lost. Reconnecting in 5s...");
                }
                Err(e) => {
                    warn!("[PolyClient] Connect Failed: {}. Retrying in 5s...", e);
                }
            }
            smol::Timer::after(Duration::from_secs(5)).await;
        }
    }

    async fn write_frame<W>(&self, writer: &mut W, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> 
    where W: AsyncWriteExt + Unpin 
    {
        let cipher = ChaCha20Poly1305::new(&self.master_key);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "E80"))?;

        let mut final_payload = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        final_payload.extend_from_slice(&nonce_bytes);
        final_payload.extend_from_slice(&ciphertext);

        let packet = MqttPacket::new(AUTH_TOPIC, final_payload).to_bytes()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        writer.write_all(&packet).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn read_frame<R>(&self, reader: &mut R) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>
    where R: AsyncReadExt + Unpin
    {
        let mut head = [0u8; 1];
        reader.read_exact(&mut head).await?;
        
        if (head[0] & 0xF0) != 0x30 {
            return Err(format!("Invalid MQTT header: 0x{:02X}", head[0]).into());
        }
        
        let len = self.decode_var_length(reader).await?;
        
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;
        
        if body.len() < 2 { return Err("Body too short".into()); }
        let topic_len = ((body[0] as usize) << 8) | (body[1] as usize);
        if body.len() < 2 + topic_len { return Err("Body shorter than topic".into()); }
        
        let encrypted_payload = &body[2 + topic_len..];
        
        if encrypted_payload.len() < 12 {
             return Err("Payload too short for Nonce".into());
        }

        let nonce = Nonce::from_slice(&encrypted_payload[0..12]);
        let ciphertext = &encrypted_payload[12..];

        let cipher = ChaCha20Poly1305::new(&self.master_key);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "E81"))?;

        Ok(plaintext)
    }

    async fn write_packet(&self, stream: &mut TcpStream, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.write_frame(stream, data).await
    }

    async fn decode_var_length<R>(&self, reader: &mut R) -> Result<usize, Box<dyn Error + Send + Sync>>
    where R: AsyncReadExt + Unpin
    {
        let mut multiplier = 1;
        let mut value = 0;
        loop {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b).await?;
            value += ((b[0] & 127) as usize) * multiplier;
            if (b[0] & 128) == 0 { break; }
            multiplier *= 128;
            if multiplier > 128*128*128 { return Err("VarLen Too Big".into()); }
        }
        Ok(value)
    }
}
