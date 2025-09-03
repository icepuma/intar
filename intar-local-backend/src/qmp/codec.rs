use bytes::{BufMut, BytesMut};
use serde_json::Value;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/// JSON line-based codec for QMP protocol
/// Each JSON message is terminated by a newline character
pub struct QmpCodec;

impl QmpCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Default for QmpCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for QmpCodec {
    type Item = Value;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Look for a newline to frame the JSON message
        if let Some(newline_offset) = buf.iter().position(|b| *b == b'\n') {
            // Split off the complete line including newline
            let line = buf.split_to(newline_offset + 1);

            // Remove the newline character for parsing
            let json_bytes = &line[..line.len() - 1];

            // Skip empty lines
            if json_bytes.is_empty() {
                return Ok(None);
            }

            // Parse the JSON
            match serde_json::from_slice(json_bytes) {
                Ok(value) => Ok(Some(value)),
                Err(e) => {
                    let context = String::from_utf8_lossy(json_bytes);
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to parse JSON: {} | Content: {}", e, context),
                    ))
                }
            }
        } else {
            // Not enough data for a complete message
            Ok(None)
        }
    }
}

impl Encoder<Value> for QmpCodec {
    type Error = io::Error;

    fn encode(&mut self, value: Value, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // Serialize to JSON
        let json_bytes = serde_json::to_vec(&value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Reserve space for JSON + newline
        buf.reserve(json_bytes.len() + 1);

        // Write JSON and newline
        buf.put_slice(&json_bytes);
        buf.put_u8(b'\n');

        Ok(())
    }
}
