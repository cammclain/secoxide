//! # brute-seco-rs (Production-Optimized - Rainbow Table Version)
//!
//! This tool recovers an Exodus wallet’s seed (or secret) from encrypted `.seco` files.
//! It parses the file header, derives the key using scrypt, and decrypts the ciphertext
//! using AES-256-GCM. It processes an entire directory of `.seco` files concurrently,
//! uses Rayon to parallelize candidate password processing, and provides real-time logging
//! and progress output.
//!
//! ## File Format (Hypothetical)
//! - 4 bytes: Magic ("SECO")
//! - 1 byte: Version (0 or 1)
//! - 1 byte: Salt length (e.g., 16)
//! - Salt (variable)
//! - 1 byte: IV length (e.g., 12)
//! - IV (variable)
//! - 1 byte: Tag length (e.g., 16)
//! - Tag (variable)
//! - Ciphertext (rest of file)
//!
//! ## Cryptography
//! - Key derivation via scrypt with fixed parameters: N=16384, r=8, p=1.
//! - Decryption via AES-256-GCM.
//!
//! ## Usage
//!
//! ```sh
//! cargo build --release
//! ./target/release/brute-seco-rs --directory /path/to/seco_dir --wordlist /path/to/wordlist.txt --verbose
//! ```
//!
//! ## Disclaimer
//! This code is provided as an example. Make sure to audit and test thoroughly before using in production.

use anyhow::{anyhow, Context, Result};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use scrypt::{scrypt, Params as ScryptParams};
use std::{
    collections::HashMap,
    fs,
    path::{PathBuf},
    sync::{Arc, Mutex},
};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use log::{error, info};
use hex;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Directory containing .seco files.
    #[arg(short, long)]
    directory: PathBuf,

    /// Wordlist file path (one candidate password per line).
    #[arg(short, long)]
    wordlist: PathBuf,

    /// Enable verbose logging.
    #[arg(short, long)]
    verbose: bool,
}

/// Represents the parsed contents of a .seco file.
struct SecoFile {
    salt: Vec<u8>,
    iv: Vec<u8>,
    tag: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Parse a .seco file from a byte slice.
/// Accepts version 0 and 1.
/// Expects the following layout:
/// - 4 bytes: Magic ("SECO")
/// - 1 byte: Version (0 or 1)
/// - 1 byte: Salt length
/// - Salt bytes
/// - 1 byte: IV length
/// - IV bytes
/// - 1 byte: Tag length
/// - Tag bytes
/// - Remaining: Ciphertext
fn parse_seco_file(data: &[u8]) -> Result<SecoFile> {
    if data.len() < 4 {
        return Err(anyhow!("File too small to contain magic bytes"));
    }
    if &data[0..4] != b"SECO" {
        return Err(anyhow!("Invalid magic bytes; not a SECO file"));
    }
    let mut offset = 4;
    if data.len() < offset + 1 {
        return Err(anyhow!("Unexpected EOF reading version"));
    }
    let version = data[offset];
    offset += 1;
    // Accept version 0 or 1.
    if version != 0 && version != 1 {
        return Err(anyhow!("Unsupported SECO version: {}", version));
    } else {
        info!("SECO version {} detected, proceeding.", version);
    }
    if data.len() < offset + 1 {
        return Err(anyhow!("Unexpected EOF reading salt length"));
    }
    let salt_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + salt_len {
        return Err(anyhow!("Unexpected EOF reading salt"));
    }
    let salt = data[offset..offset + salt_len].to_vec();
    offset += salt_len;

    if data.len() < offset + 1 {
        return Err(anyhow!("Unexpected EOF reading IV length"));
    }
    let iv_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + iv_len {
        return Err(anyhow!("Unexpected EOF reading IV"));
    }
    let iv = data[offset..offset + iv_len].to_vec();
    offset += iv_len;

    if data.len() < offset + 1 {
        return Err(anyhow!("Unexpected EOF reading tag length"));
    }
    let tag_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + tag_len {
        return Err(anyhow!("Unexpected EOF reading tag"));
    }
    let tag = data[offset..offset + tag_len].to_vec();
    offset += tag_len;

    // The rest is ciphertext.
    let ciphertext = data[offset..].to_vec();

    Ok(SecoFile {
        salt,
        iv,
        tag,
        ciphertext,
    })
}

/// Derive a 32-byte key from a candidate password and salt using scrypt.
fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    let scrypt_params = ScryptParams::new(14, 8, 1).expect("Invalid scrypt parameters");
    let mut key = [0u8; 32];
    scrypt(password.as_bytes(), salt, &scrypt_params, &mut key)
        .expect("scrypt key derivation failed");
    key.to_vec()
}

/// Attempts to decrypt the given SecoFile using the provided candidate password.
/// Derives a key using scrypt and then uses AES-256-GCM to decrypt the ciphertext.
/// Returns the decrypted plaintext if successful.
fn decrypt_seco(seco: &SecoFile, candidate: &str) -> Result<String> {
    let key = derive_key(candidate, &seco.salt);
    let cipher = Aes256Gcm::new_from_slice(&key).context("Key init failed")?;

    if seco.iv.len() != 12 {
        return Err(anyhow!("Invalid IV length: expected 12, got {}", seco.iv.len()));
    }
    let nonce = Nonce::from_slice(&seco.iv);

    // Combine ciphertext and tag as expected by the aes-gcm crate.
    let mut combined = seco.ciphertext.clone();
    combined.extend_from_slice(&seco.tag);

    let decrypted = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| anyhow!("Decryption failed (likely wrong password): {:?}", e))?;

    let plaintext = String::from_utf8(decrypted)
        .context("Decrypted data is not valid UTF-8")?;
    Ok(plaintext)
}

/// Process a single `.seco` file using a rainbow table approach.
/// Reads the file asynchronously, parses it, builds a rainbow table in parallel,
/// and attempts decryption for each candidate password.
async fn process_file(
    file_path: PathBuf,
    wordlist: Arc<Vec<String>>,
    mp: &MultiProgress,
) -> FileResult {
    info!("Processing file: {:?}", file_path);
    let pb = mp.add(ProgressBar::new(wordlist.len() as u64));
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    let file_msg = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    pb.set_message(file_msg);

    let mut file = match File::open(&file_path).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open file {:?}: {:?}", file_path, e);
            pb.finish_with_message("Failed to open file");
            return FileResult {
                file_path,
                recovered_password: None,
            };
        }
    };
    let mut data = Vec::new();
    if let Err(e) = file.read_to_end(&mut data).await {
        error!("Failed to read file {:?}: {:?}", file_path, e);
        pb.finish_with_message("Failed to read file");
        return FileResult {
            file_path,
            recovered_password: None,
        };
    }

    let seco = match parse_seco_file(&data) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse file {:?}: {:?}", file_path, e);
            pb.finish_with_message("Parse error");
            return FileResult {
                file_path,
                recovered_password: None,
            };
        }
    };

    // Build the rainbow table in parallel: mapping derived key hex -> candidate password.
    let rainbow_table: HashMap<String, String> = wordlist
        .par_iter()
        .map(|candidate| {
            let key = derive_key(candidate, &seco.salt);
            (hex::encode(&key), candidate.clone())
        })
        .collect();
    pb.println(format!(
        "Rainbow table built with {} entries",
        rainbow_table.len()
    ));

    // Try decryption for each candidate password in parallel.
    let result = Arc::new(Mutex::new(None));
    wordlist.par_iter().for_each(|candidate| {
        pb.inc(1);
        if let Ok(_plaintext) = decrypt_seco(&seco, candidate) {
            let mut res_lock = result.lock().unwrap();
            if res_lock.is_none() {
                *res_lock = Some(candidate.clone());
                info!("File {:?}: PASSWORD FOUND -> {}", file_path, candidate);
            }
        }
    });
    pb.finish_with_message("Done");

    let recovered = result.lock().unwrap().clone();
    FileResult {
        file_path,
        recovered_password: recovered,
    }
}

/// Main function:
/// - Parses CLI arguments.
/// - Loads the wordlist (using a lossy conversion to handle non-UTF8 data).
/// - Scans the specified directory for `.seco` files.
/// - Spawns concurrent tasks to process each file.
/// - Waits for all tasks and then prints a summary.
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::init();
    }
    info!("Starting brute-seco-rs (production-optimized version)");

    // Read wordlist as bytes, then convert using from_utf8_lossy to handle non-UTF8 input.
    let wordlist_bytes = fs::read(&args.wordlist)
        .with_context(|| format!("Failed to read wordlist file {:?}", args.wordlist))?;
    let wordlist_data = String::from_utf8_lossy(&wordlist_bytes);
    let wordlist: Vec<String> = wordlist_data
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    info!("Loaded {} candidate passwords", wordlist.len());
    let wordlist = Arc::new(wordlist);

    let mut seco_files = Vec::new();
    for entry in fs::read_dir(&args.directory)
        .with_context(|| format!("Failed to read directory {:?}", args.directory))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()).unwrap_or("") == "seco" {
            seco_files.push(path);
        }
    }
    info!("Found {} .seco files", seco_files.len());

    let mp = Arc::new(MultiProgress::new());
    let mut tasks = Vec::new();
    for file_path in seco_files {
        let wordlist = Arc::clone(&wordlist);
        let mp = mp.clone();
        let task = tokio::spawn(async move { process_file(file_path, wordlist, &mp).await });
        tasks.push(task);
    }
    let results = futures::future::join_all(tasks).await;
    let mut summary = Vec::new();
    for res in results {
        match res {
            Ok(file_result) => summary.push(file_result),
            Err(e) => error!("Task failed: {:?}", e),
        }
    }
    println!("\nSummary of Recovery Results:");
    for file_result in summary {
        let fname = file_result
            .file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        match file_result.recovered_password {
            Some(pwd) => println!("{}: PASSWORD FOUND -> {}", fname, pwd),
            None => println!("{}: NO PASSWORD FOUND", fname),
        }
    }
    Ok(())
}

/// Struct to hold file processing result.
struct FileResult {
    file_path: PathBuf,
    recovered_password: Option<String>,
}
