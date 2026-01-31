use std::io::{self, Cursor, Read, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

pub const MQTT_PUBLISH: u8 = 0x30;
pub const MAX_TOPIC_LEN: usize = 256;

#[derive(Debug, Clone)]
pub struct MqttPacket {
    pub topic: String,
    pub payload: Vec<u8>,
}

impl MqttPacket {
    pub fn new(topic: &str, payload: Vec<u8>) -> Self {
        Self {
            topic: topic.to_string(),
            payload,
        }
    }

    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let topic_bytes = self.topic.as_bytes();
        let remaining_len = 2 + topic_bytes.len() + self.payload.len();
        
        buf.write_u8(MQTT_PUBLISH)?;
        encode_var_length(remaining_len, &mut buf)?;
        buf.write_u16::<BigEndian>(topic_bytes.len() as u16)?;
        buf.write_all(topic_bytes)?;
        buf.write_all(&self.payload)?;
        
        Ok(buf)
    }

    pub fn parse(buffer: &[u8]) -> io::Result<Self> {
        let mut rdr = Cursor::new(buffer);
        
        let header = rdr.read_u8()?;
        if (header & 0xF0) != 0x30 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid MQTT Header"));
        }
        
        let _len = decode_var_length(&mut rdr)?;
        let topic_len = rdr.read_u16::<BigEndian>()? as usize;
        
        if topic_len > MAX_TOPIC_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Topic too long"));
        }
        let mut topic_buf = vec![0u8; topic_len];
        rdr.read_exact(&mut topic_buf)?;
        let topic = String::from_utf8(topic_buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 Topic"))?;
            
        let mut payload = Vec::new();
        rdr.read_to_end(&mut payload)?;
        
        Ok(Self { topic, payload })
    }
}

// MQTT Variable Byte Integer Encoding
fn encode_var_length(mut len: usize, buf: &mut Vec<u8>) -> io::Result<()> {
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 { byte |= 128; }
        buf.write_u8(byte)?;
        if len == 0 { break; }
    }
    Ok(())
}

fn decode_var_length<R: Read>(rdr: &mut R) -> io::Result<usize> {
    let mut multiplier = 1;
    let mut value = 0;
    loop {
        let byte = rdr.read_u8()?;
        value += ((byte & 127) as usize) * multiplier;
        if (byte & 128) == 0 { break; }
        multiplier *= 128;
        if multiplier > 128*128*128 { 
            return Err(io::Error::new(io::ErrorKind::InvalidData, "VarLen Too Big")); 
        }
    }
    Ok(value)
}
