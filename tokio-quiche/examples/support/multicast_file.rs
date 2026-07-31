// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![allow(dead_code)]
// This helper module is compiled separately into the client and server
// examples, so each example sees the other side's utilities as unused.

use std::collections::hash_map::DefaultHasher;
use std::future::pending;
use std::future::Future;
use std::hash::Hash;
use std::hash::Hasher;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::QuicResult;

const FILE_PACKET_MAGIC: [u8; 4] = *b"QMCF";
const FILE_PACKET_VERSION: u8 = 1;
const FILE_PACKET_KIND_MANIFEST: u8 = 1;
const FILE_PACKET_KIND_CHUNK: u8 = 2;

pub const DEFAULT_ENCRYPTION_ALGORITHM: u16 = 0x1301;
pub const DEFAULT_HASH_ALGORITHM: u16 = 1;
pub const DEFAULT_HASH_ALGORITHM_NAME: &str = "sha256-32";
pub const DEFAULT_HEADER_SECRET: [u8; 16] = [0xaa; 16];
pub const DEFAULT_PAYLOAD_SECRET: [u8; 16] = [0xcc; 16];
pub const FILE_CHANNEL_ID: [u8; 8] = *b"qmcfile1";

pub fn parse_hash_algorithm_id(value: &str) -> anyhow::Result<u16> {
    let normalized = value.trim().to_ascii_lowercase();

    match normalized.as_str() {
        "1" | "sha256" | "sha256-32" => Ok(1),
        "2" | "sha256-16" => Ok(2),
        "3" | "sha256-15" => Ok(3),
        "4" | "sha256-12" => Ok(4),
        "5" | "sha256-8" => Ok(5),
        "6" | "sha256-4" => Ok(6),
        "7" | "sha384" | "sha384-48" => Ok(7),
        "8" | "sha512" | "sha512-64" => Ok(8),

        _ => anyhow::bail!(
            "unknown integrity hash algorithm `{value}`; expected one of \
             sha256-32, sha256-16, sha256-15, sha256-12, sha256-8, \
             sha256-4, sha384-48, sha512-64"
        ),
    }
}

pub fn describe_hash_algorithm(id: u16) -> &'static str {
    match id {
        1 => "sha256-32",
        2 => "sha256-16",
        3 => "sha256-15",
        4 => "sha256-12",
        5 => "sha256-8",
        6 => "sha256-4",
        7 => "sha384-48",
        8 => "sha512-64",
        _ => "unknown",
    }
}

pub fn hash_algorithm_output_len(id: u16) -> anyhow::Result<usize> {
    Ok(match id {
        1 => 32,
        2 => 16,
        3 => 15,
        4 => 12,
        5 => 8,
        6 => 4,
        7 => 48,
        8 => 64,

        _ => anyhow::bail!("unknown integrity hash algorithm id `{id}`"),
    })
}

pub struct IdleApp;

impl IdleApp {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IdleApp {
    fn default() -> Self {
        Self::new()
    }
}

impl ApplicationOverQuic for IdleApp {
    fn on_conn_established(
        &mut self, _qconn: &mut QuicheConnection, _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn wait_for_data(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        pending::<QuicResult<()>>()
    }

    fn process_reads(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        Ok(())
    }

    fn process_writes(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        Ok(())
    }

    fn on_conn_close<M: tokio_quiche::metrics::Metrics>(
        &mut self, qconn: &mut QuicheConnection, _metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        let stats = qconn.stats();
        println!(
            "control connection closed: result={} detail={:?} local_error={:?} \
             peer_error={:?} sent={} recv={} lost={} retrans={} sent_bytes={} \
             recv_bytes={}",
            if connection_result.is_ok() {
                "ok"
            } else {
                "error"
            },
            connection_result,
            qconn.local_error(),
            qconn.peer_error(),
            stats.sent,
            stats.recv,
            stats.lost,
            stats.retrans,
            stats.sent_bytes,
            stats.recv_bytes,
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileManifest {
    pub transfer_id: u64,
    pub file_name: String,
    pub file_len: u64,
    pub chunk_payload_len: u32,
    pub total_chunks: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTransfer {
    manifest: FileManifest,
    bytes: Arc<[u8]>,
}

impl PreparedTransfer {
    pub fn from_path(
        path: &Path, chunk_payload_len: usize,
    ) -> anyhow::Result<Self> {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("file path must end in a valid UTF-8 file name")?
            .to_string();
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        Self::from_bytes(file_name, bytes, chunk_payload_len)
    }

    pub fn from_bytes(
        file_name: String, bytes: Vec<u8>, chunk_payload_len: usize,
    ) -> anyhow::Result<Self> {
        if chunk_payload_len == 0 {
            anyhow::bail!("chunk payload length must be greater than zero");
        }

        let chunk_payload_len = u32::try_from(chunk_payload_len)
            .context("chunk payload length is too large")?;
        let total_chunks = if bytes.is_empty() {
            0
        } else {
            let chunk_len = usize::try_from(chunk_payload_len).unwrap();
            bytes.len().div_ceil(chunk_len)
        };
        let total_chunks = u32::try_from(total_chunks)
            .context("file requires too many chunks")?;
        let file_len = u64::try_from(bytes.len())
            .context("file is too large to describe")?;
        let transfer_id = compute_transfer_id(
            &file_name,
            &bytes,
            usize::try_from(chunk_payload_len).unwrap(),
        );

        if file_name.len() > usize::from(u16::MAX) {
            anyhow::bail!("file name is too long for the example wire format");
        }

        Ok(Self {
            manifest: FileManifest {
                transfer_id,
                file_name,
                file_len,
                chunk_payload_len,
                total_chunks,
            },
            bytes: Arc::<[u8]>::from(bytes),
        })
    }

    pub fn manifest(&self) -> &FileManifest {
        &self.manifest
    }

    pub fn chunk_bytes(&self, chunk_index: u32) -> Option<&[u8]> {
        if chunk_index >= self.manifest.total_chunks {
            return None;
        }

        let chunk_len = usize::try_from(self.manifest.chunk_payload_len).ok()?;
        let start = usize::try_from(chunk_index).ok()?.checked_mul(chunk_len)?;
        let end = self.bytes.len().min(start.checked_add(chunk_len)?);
        self.bytes.get(start..end)
    }
}

#[derive(Clone)]
pub struct LoopingTransfer {
    transfer: PreparedTransfer,
    next_chunk_index: u32,
    packets_since_manifest: u32,
    manifest_interval_packets: u32,
}

impl LoopingTransfer {
    pub fn new(
        transfer: PreparedTransfer, manifest_interval_packets: u32,
    ) -> anyhow::Result<Self> {
        if manifest_interval_packets == 0 {
            anyhow::bail!("manifest interval must be at least one packet");
        }

        Ok(Self {
            transfer,
            next_chunk_index: 0,
            packets_since_manifest: manifest_interval_packets,
            manifest_interval_packets,
        })
    }

    pub fn next_datagram(&mut self) -> Vec<u8> {
        if self.transfer.manifest.total_chunks == 0 ||
            self.packets_since_manifest >= self.manifest_interval_packets
        {
            self.packets_since_manifest = 0;
            return encode_manifest(&self.transfer.manifest);
        }

        let chunk_index = self.next_chunk_index;
        self.next_chunk_index = if self.transfer.manifest.total_chunks == 0 {
            0
        } else {
            (chunk_index + 1) % self.transfer.manifest.total_chunks
        };
        self.packets_since_manifest += 1;

        encode_chunk(
            self.transfer.manifest.transfer_id,
            chunk_index,
            self.transfer.chunk_bytes(chunk_index).unwrap_or_default(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileChunk {
    pub transfer_id: u64,
    pub chunk_index: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilePacket {
    Manifest(FileManifest),
    Chunk(FileChunk),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedFile {
    pub manifest: FileManifest,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiveUpdate {
    Ignored,
    Manifest(FileManifest),
    ChunkStored {
        chunk_index: u32,
        received_chunks: u32,
        total_chunks: u32,
    },
    Complete(CompletedFile),
}

#[derive(Default)]
pub struct FileReceiver {
    manifest: Option<FileManifest>,
    bytes: Vec<u8>,
    received_chunks: Vec<bool>,
    received_count: u32,
}

impl FileReceiver {
    pub fn apply(&mut self, packet: FilePacket) -> Result<ReceiveUpdate, String> {
        match packet {
            FilePacket::Manifest(manifest) => self.apply_manifest(manifest),
            FilePacket::Chunk(chunk) => self.apply_chunk(chunk),
        }
    }

    fn apply_manifest(
        &mut self, manifest: FileManifest,
    ) -> Result<ReceiveUpdate, String> {
        if self.manifest.as_ref() == Some(&manifest) {
            return Ok(ReceiveUpdate::Ignored);
        }

        let file_len = usize::try_from(manifest.file_len)
            .map_err(|_| "manifest file length exceeds local address space")?;
        let total_chunks = usize::try_from(manifest.total_chunks)
            .map_err(|_| "manifest chunk count exceeds local address space")?;

        self.bytes = vec![0; file_len];
        self.received_chunks = vec![false; total_chunks];
        self.received_count = 0;
        self.manifest = Some(manifest.clone());

        if manifest.total_chunks == 0 {
            return Ok(ReceiveUpdate::Complete(CompletedFile {
                manifest,
                bytes: Vec::new(),
            }));
        }

        Ok(ReceiveUpdate::Manifest(manifest))
    }

    fn apply_chunk(&mut self, chunk: FileChunk) -> Result<ReceiveUpdate, String> {
        let manifest = match self.manifest.as_ref() {
            Some(manifest) if manifest.transfer_id == chunk.transfer_id =>
                manifest,
            _ => return Ok(ReceiveUpdate::Ignored),
        };

        if chunk.chunk_index >= manifest.total_chunks {
            return Err(format!(
                "chunk index {} exceeds total chunk count {}",
                chunk.chunk_index, manifest.total_chunks
            ));
        }

        let chunk_len =
            usize::try_from(manifest.chunk_payload_len).map_err(|_| {
                "manifest chunk payload length exceeds local address space"
            })?;
        let chunk_index = usize::try_from(chunk.chunk_index)
            .map_err(|_| "chunk index exceeds local address space")?;
        let start = chunk_index
            .checked_mul(chunk_len)
            .ok_or("chunk offset overflow")?;
        let expected_len = if chunk.chunk_index + 1 == manifest.total_chunks {
            self.bytes
                .len()
                .checked_sub(start)
                .ok_or("final chunk offset exceeds file length")?
        } else {
            chunk_len
        };

        if chunk.data.len() != expected_len {
            return Err(format!(
                "chunk {} had {} bytes, expected {}",
                chunk.chunk_index,
                chunk.data.len(),
                expected_len
            ));
        }

        if self.received_chunks[chunk_index] {
            return Ok(ReceiveUpdate::Ignored);
        }

        let end = start
            .checked_add(expected_len)
            .ok_or("chunk end overflow")?;
        self.bytes[start..end].copy_from_slice(&chunk.data);
        self.received_chunks[chunk_index] = true;
        self.received_count += 1;

        if self.received_count == manifest.total_chunks {
            return Ok(ReceiveUpdate::Complete(CompletedFile {
                manifest: manifest.clone(),
                bytes: self.bytes.clone(),
            }));
        }

        Ok(ReceiveUpdate::ChunkStored {
            chunk_index: chunk.chunk_index,
            received_chunks: self.received_count,
            total_chunks: manifest.total_chunks,
        })
    }
}

pub fn decode_file_packet(data: &[u8]) -> Result<Option<FilePacket>, String> {
    if data.len() < 6 || data[..4] != FILE_PACKET_MAGIC {
        return Ok(None);
    }

    let mut cursor = 4;
    let version = read_u8(data, &mut cursor)?;
    if version != FILE_PACKET_VERSION {
        return Err(format!("unsupported file packet version {version}"));
    }

    let kind = read_u8(data, &mut cursor)?;
    match kind {
        FILE_PACKET_KIND_MANIFEST => {
            let transfer_id = read_u64(data, &mut cursor)?;
            let file_len = read_u64(data, &mut cursor)?;
            let chunk_payload_len = read_u32(data, &mut cursor)?;
            let total_chunks = read_u32(data, &mut cursor)?;
            let file_name_len = usize::from(read_u16(data, &mut cursor)?);
            let file_name_bytes = take_bytes(data, &mut cursor, file_name_len)?;
            let file_name = String::from_utf8(file_name_bytes.to_vec())
                .map_err(|_| "manifest file name was not valid UTF-8")?;

            if cursor != data.len() {
                return Err("manifest packet had trailing bytes".to_string());
            }

            Ok(Some(FilePacket::Manifest(FileManifest {
                transfer_id,
                file_name,
                file_len,
                chunk_payload_len,
                total_chunks,
            })))
        },

        FILE_PACKET_KIND_CHUNK => {
            let transfer_id = read_u64(data, &mut cursor)?;
            let chunk_index = read_u32(data, &mut cursor)?;
            let payload_len = usize::try_from(read_u32(data, &mut cursor)?)
                .map_err(|_| {
                    "chunk payload length exceeds local address space"
                })?;
            let payload = take_bytes(data, &mut cursor, payload_len)?;

            if cursor != data.len() {
                return Err("chunk packet had trailing bytes".to_string());
            }

            Ok(Some(FilePacket::Chunk(FileChunk {
                transfer_id,
                chunk_index,
                data: payload.to_vec(),
            })))
        },

        other => Err(format!("unknown file packet kind {other}")),
    }
}

fn compute_transfer_id(
    file_name: &str, bytes: &[u8], chunk_payload_len: usize,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    file_name.hash(&mut hasher);
    bytes.len().hash(&mut hasher);
    chunk_payload_len.hash(&mut hasher);
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn encode_manifest(manifest: &FileManifest) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(4 + 2 + 8 + 8 + 4 + 4 + 2 + manifest.file_name.len());
    out.extend_from_slice(&FILE_PACKET_MAGIC);
    out.push(FILE_PACKET_VERSION);
    out.push(FILE_PACKET_KIND_MANIFEST);
    write_u64(&mut out, manifest.transfer_id);
    write_u64(&mut out, manifest.file_len);
    write_u32(&mut out, manifest.chunk_payload_len);
    write_u32(&mut out, manifest.total_chunks);
    write_u16(&mut out, manifest.file_name.len() as u16);
    out.extend_from_slice(manifest.file_name.as_bytes());
    out
}

fn encode_chunk(transfer_id: u64, chunk_index: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 + 8 + 4 + 4 + payload.len());
    out.extend_from_slice(&FILE_PACKET_MAGIC);
    out.push(FILE_PACKET_VERSION);
    out.push(FILE_PACKET_KIND_CHUNK);
    write_u64(&mut out, transfer_id);
    write_u32(&mut out, chunk_index);
    write_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    out
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, String> {
    let bytes = take_bytes(data, cursor, 1)?;
    Ok(bytes[0])
}

fn read_u16(data: &[u8], cursor: &mut usize) -> Result<u16, String> {
    let bytes = take_bytes(data, cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let bytes = take_bytes(data, cursor, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], cursor: &mut usize) -> Result<u64, String> {
    let bytes = take_bytes(data, cursor, 8)?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
        bytes[7],
    ]))
}

fn take_bytes<'a>(
    data: &'a [u8], cursor: &mut usize, len: usize,
) -> Result<&'a [u8], String> {
    let end = cursor
        .checked_add(len)
        .ok_or("packet cursor overflow".to_string())?;
    let bytes = data
        .get(*cursor..end)
        .ok_or("packet was truncated".to_string())?;
    *cursor = end;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip() {
        let manifest = FileManifest {
            transfer_id: 7,
            file_name: "hello.txt".to_string(),
            file_len: 13,
            chunk_payload_len: 4,
            total_chunks: 4,
        };

        let decoded = decode_file_packet(&encode_manifest(&manifest))
            .unwrap()
            .unwrap();

        assert_eq!(decoded, FilePacket::Manifest(manifest));
    }

    #[test]
    fn manifest_rejects_trailing_bytes() {
        let manifest = FileManifest {
            transfer_id: 7,
            file_name: "hello.txt".to_string(),
            file_len: 13,
            chunk_payload_len: 4,
            total_chunks: 4,
        };
        let mut packet = encode_manifest(&manifest);
        packet.push(0);

        let err = decode_file_packet(&packet).unwrap_err();

        assert_eq!(err, "manifest packet had trailing bytes");
    }

    #[test]
    fn chunk_roundtrip() {
        let decoded = decode_file_packet(&encode_chunk(9, 3, b"abcd"))
            .unwrap()
            .unwrap();

        assert_eq!(
            decoded,
            FilePacket::Chunk(FileChunk {
                transfer_id: 9,
                chunk_index: 3,
                data: b"abcd".to_vec(),
            })
        );
    }

    #[test]
    fn receiver_reassembles_chunks() {
        let transfer = PreparedTransfer::from_bytes(
            "hello.txt".to_string(),
            b"hello multicast".to_vec(),
            5,
        )
        .unwrap();
        let manifest = transfer.manifest().clone();
        let mut receiver = FileReceiver::default();

        assert_eq!(
            receiver
                .apply(FilePacket::Manifest(manifest.clone()))
                .unwrap(),
            ReceiveUpdate::Manifest(manifest.clone())
        );
        assert_eq!(
            receiver
                .apply(FilePacket::Chunk(FileChunk {
                    transfer_id: manifest.transfer_id,
                    chunk_index: 1,
                    data: transfer.chunk_bytes(1).unwrap().to_vec(),
                }))
                .unwrap(),
            ReceiveUpdate::ChunkStored {
                chunk_index: 1,
                received_chunks: 1,
                total_chunks: manifest.total_chunks,
            }
        );

        let complete = receiver
            .apply(FilePacket::Chunk(FileChunk {
                transfer_id: manifest.transfer_id,
                chunk_index: 0,
                data: transfer.chunk_bytes(0).unwrap().to_vec(),
            }))
            .unwrap();

        assert!(matches!(complete, ReceiveUpdate::ChunkStored { .. }));

        let complete = receiver
            .apply(FilePacket::Chunk(FileChunk {
                transfer_id: manifest.transfer_id,
                chunk_index: 2,
                data: transfer.chunk_bytes(2).unwrap().to_vec(),
            }))
            .unwrap();

        assert_eq!(
            complete,
            ReceiveUpdate::Complete(CompletedFile {
                manifest,
                bytes: b"hello multicast".to_vec(),
            })
        );
    }
}
