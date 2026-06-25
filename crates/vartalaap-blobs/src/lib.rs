//! End-to-end-encrypted file transfer primitives for Vartalaap.
//!
//! A file is transferred in two parts:
//! 1. a [`FileMeta`] (name, size, mime, content hash, and a fresh random
//!    symmetric key) sent **inside the E2E ratchet** as part of a chat message;
//! 2. the file bytes, split into chunks and each sealed with that key, streamed
//!    over a dedicated QUIC stream.
//!
//! Because the per-file key travels end-to-end and the bytes are sealed with it,
//! file *content* is private even from the transport — not just TLS-on-the-wire.
//! The receiver verifies the SHA-256 of the reassembled plaintext against
//! [`FileMeta::sha256`], so truncation or tampering is detected.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vartalaap_crypto::{open, seal, CryptoError, VaultKey};

/// Plaintext bytes per chunk before sealing.
pub const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("content hash mismatch: file is corrupt or truncated")]
    HashMismatch,
}

/// Metadata describing a file offer. The `key` is secret and only ever travels
/// inside the end-to-end-encrypted channel.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMeta {
    pub transfer_id: [u8; 16],
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub sha256: [u8; 32],
    pub key: [u8; 32],
}

/// Stream a file once to compute its SHA-256 and size, without loading it all
/// into memory.
pub fn hash_file(path: &Path) -> Result<([u8; 32], u64), BlobError> {
    let mut f = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hasher.finalize().into(), size))
}

/// Build a [`FileMeta`] for `path` with a fresh transfer id and encryption key.
pub fn prepare(path: &Path) -> Result<FileMeta, BlobError> {
    let (sha256, size) = hash_file(path)?;
    let mut transfer_id = [0u8; 16];
    let mut key = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut transfer_id);
    rng.fill_bytes(&mut key);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    Ok(FileMeta {
        transfer_id,
        name,
        size,
        mime: guess_mime(path),
        sha256,
        key,
    })
}

/// Reads a file and yields sealed chunks one at a time.
pub struct EncryptStream {
    reader: BufReader<File>,
    key: VaultKey,
}

impl EncryptStream {
    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self, BlobError> {
        Ok(Self {
            reader: BufReader::new(File::open(path)?),
            key: VaultKey::from(key),
        })
    }

    /// The next sealed chunk, or `None` at end of file.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, BlobError> {
        let mut buf = vec![0u8; CHUNK];
        let n = read_fill(&mut self.reader, &mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some(seal(&self.key, &buf)))
    }
}

/// Writes decrypted chunks to a destination file, tracking the running hash.
pub struct DecryptSink {
    writer: BufWriter<File>,
    key: VaultKey,
    hasher: Sha256,
    path: PathBuf,
}

impl DecryptSink {
    pub fn create(path: &Path, key: [u8; 32]) -> Result<Self, BlobError> {
        Ok(Self {
            writer: BufWriter::new(File::create(path)?),
            key: VaultKey::from(key),
            hasher: Sha256::new(),
            path: path.to_path_buf(),
        })
    }

    /// Decrypt one sealed chunk and append it to the file.
    pub fn write_chunk(&mut self, ciphertext: &[u8]) -> Result<(), BlobError> {
        let plain = open(&self.key, ciphertext)?;
        self.hasher.update(&plain);
        self.writer.write_all(&plain)?;
        Ok(())
    }

    /// Flush and verify the reassembled content matches `expected_sha256`.
    /// Returns the written path on success.
    pub fn finish(mut self, expected_sha256: [u8; 32]) -> Result<PathBuf, BlobError> {
        self.writer.flush()?;
        let got: [u8; 32] = self.hasher.finalize().into();
        if got != expected_sha256 {
            return Err(BlobError::HashMismatch);
        }
        Ok(self.path)
    }
}

/// Read until `buf` is full or EOF; returns the number of bytes read.
fn read_fill(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

fn guess_mime(path: &Path) -> String {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let m = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        "zip" => "application/zip",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    };
    m.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = rand::random();
        p.push(format!("vartalaap-blob-{n}-{name}"));
        p
    }

    fn write_random(path: &Path, len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut data);
        std::fs::write(path, &data).unwrap();
        data
    }

    #[test]
    fn roundtrip_multi_chunk_file() {
        let src = tmp("src.bin");
        // 150 KiB → spans multiple 64 KiB chunks.
        let original = write_random(&src, CHUNK * 2 + 1234);
        let meta = prepare(&src).unwrap();
        assert_eq!(meta.size, original.len() as u64);

        let dst = tmp("dst.bin");
        let mut enc = EncryptStream::open(&src, meta.key).unwrap();
        let mut sink = DecryptSink::create(&dst, meta.key).unwrap();
        let mut chunks = 0;
        while let Some(c) = enc.next_chunk().unwrap() {
            sink.write_chunk(&c).unwrap();
            chunks += 1;
        }
        assert!(chunks >= 3, "expected multiple chunks, got {chunks}");
        let out = sink.finish(meta.sha256).unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), original);
        std::fs::remove_file(&src).ok();
        std::fs::remove_file(&dst).ok();
    }

    #[test]
    fn tampered_chunk_is_rejected() {
        let src = tmp("src2.bin");
        write_random(&src, 4096);
        let meta = prepare(&src).unwrap();
        let dst = tmp("dst2.bin");

        let mut enc = EncryptStream::open(&src, meta.key).unwrap();
        let mut sink = DecryptSink::create(&dst, meta.key).unwrap();
        let mut chunk = enc.next_chunk().unwrap().unwrap();
        let last = chunk.len() - 1;
        chunk[last] ^= 0xff;
        // The AEAD seal detects tampering at decrypt time.
        assert!(sink.write_chunk(&chunk).is_err());
        std::fs::remove_file(&src).ok();
        std::fs::remove_file(&dst).ok();
    }

    #[test]
    fn wrong_total_hash_is_rejected() {
        let src = tmp("src3.bin");
        write_random(&src, 2048);
        let meta = prepare(&src).unwrap();
        let dst = tmp("dst3.bin");

        let mut enc = EncryptStream::open(&src, meta.key).unwrap();
        let mut sink = DecryptSink::create(&dst, meta.key).unwrap();
        if let Some(c) = enc.next_chunk().unwrap() {
            sink.write_chunk(&c).unwrap();
        }
        // Verify against a deliberately wrong expected hash.
        assert!(matches!(
            sink.finish([0u8; 32]),
            Err(BlobError::HashMismatch)
        ));
        std::fs::remove_file(&src).ok();
        std::fs::remove_file(&dst).ok();
    }
}
