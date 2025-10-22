use std::{fs, io::Write, path::PathBuf};

use bincode::serde::{decode_from_slice, encode_to_vec};
use clap::{Parser, Subcommand};
use hashsig::{
    MESSAGE_LENGTH,
    signature::{SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8,
    },
};
use hex::{decode as hex_decode, encode as hex_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Use a concrete scheme alias for convenience
type MySigScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;

#[derive(Serialize, Deserialize)]
struct SigEnvelope<SigT> {
    epoch: u32,
    signature: SigT,
}

#[derive(Parser, Debug)]
#[command(name = "hash-sig-example", version, about = "Hash-based signature CLI (poseidon, lifetime 2^32)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new keypair and write hex-encoded files to --output dir
    Generate {
        /// Output directory; two files will be created: pubkey.hex, secret.hex
        #[arg(long)]
        output: PathBuf,
        /// Optional: activation epoch (default: 0)
        #[arg(long, default_value_t = 0)]
        activation_epoch: usize,
        /// Optional: number of active epochs. Default keeps it small for quick generation (1024)
        #[arg(long, default_value_t = 1usize << 10)]
        num_active_epochs: usize,
    },
    /// Sign a message string at a given epoch using a secret key file (hex-encoded)
    Sign {
        /// Path to secret key file (hex without leading 0x)
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Arbitrary message string to sign (will be hashed to 32 bytes with SHA-256)
        #[arg(long)]
        message: String,
        /// Epoch number to sign for
        #[arg(long)]
        epoch: u32,
        /// Output path to write the signature (hex without leading 0x)
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Verify a signature file against a message string and public key file
    Verify {
        /// Path to signature file (hex without leading 0x). Contains the signature and epoch.
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        /// Arbitrary message string that was signed (will be hashed to 32 bytes with SHA-256)
        #[arg(long)]
        message: String,
        /// Path to public key file (hex without leading 0x)
        #[arg(long, value_name = "PATH")]
        pubkey: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { output, activation_epoch, num_active_epochs } => {
            cmd_generate(output, activation_epoch, num_active_epochs);
        }
        Commands::Sign { key, message, epoch, output } => {
            if let Err(e) = cmd_sign(key, message, epoch, output) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::Verify { signature, message, pubkey } => {
            if let Err(e) = cmd_verify(signature, message, pubkey) {
                eprintln!("Error: {e}");
                std::process::exit(2);
            }
        }
    }
}

fn cmd_generate(output_dir: PathBuf, activation_epoch: usize, num_active_epochs: usize) {
    if let Err(e) = fs::create_dir_all(&output_dir) {
        eprintln!("Failed to create output directory: {e}");
        std::process::exit(1);
    }

    let mut rng = rand::rng();
    println!("Generating key pair (activation={activation_epoch}, active_epochs={num_active_epochs})...");
    let (pk, sk) = MySigScheme::key_gen(&mut rng, activation_epoch, num_active_epochs);

    let config = bincode::config::standard();

    // Serialize and hex-encode
    let pk_bytes = encode_to_vec(&pk, config).expect("Bincode serialize pk should succeed");
    let sk_bytes = encode_to_vec(&sk, config).expect("Bincode serialize sk should succeed");

    let pk_hex = hex_encode(pk_bytes);
    let sk_hex = hex_encode(sk_bytes);

    let pk_path = output_dir.join("pubkey.hex");
    let sk_path = output_dir.join("secret.hex");

    if let Err(e) = write_string_file(&pk_path, &pk_hex) {
        eprintln!("Failed to write public key: {e}");
        std::process::exit(1);
    }
    if let Err(e) = write_string_file(&sk_path, &sk_hex) {
        eprintln!("Failed to write secret key: {e}");
        std::process::exit(1);
    }

    println!("Wrote:\n- {}\n- {}", pk_path.display(), sk_path.display());
}

fn cmd_sign(key_path: PathBuf, message_str: String, epoch: u32, output_path: PathBuf) -> Result<(), String> {
    // Read and decode secret key
    let sk_hex = read_string_file(&key_path).map_err(|e| format!("Failed to read key file: {e}"))?;
    let sk_bytes = parse_hex(&sk_hex).map_err(|e| format!("Secret key hex decode failed: {e}"))?;

    let config = bincode::config::standard();
    let (mut sk, _): (<MySigScheme as SignatureScheme>::SecretKey, _) =
        decode_from_slice(&sk_bytes, config).map_err(|e| format!("Bincode decode secret key failed: {e}"))?;

    // Convert message string to 32-byte message via SHA-256
    let message = message_to_bytes(&message_str);

    // Check activation interval before trying to prepare
    let activation = sk.get_activation_interval();
    if !(activation.start <= epoch as u64 && (epoch as u64) < activation.end) {
        return Err(format!(
            "Epoch {epoch} outside of activation interval [{}, {})",
            activation.start, activation.end
        ));
    }

    // Ensure the secret key is prepared for the target epoch, advancing if possible
    if !sk.get_prepared_interval().contains(&(epoch as u64)) {
        // Try to advance until the interval changes no further or we cover the epoch
        let mut safety = 0usize;
        loop {
            let before = sk.get_prepared_interval();
            if before.contains(&(epoch as u64)) { break; }
            sk.advance_preparation();
            let after = sk.get_prepared_interval();
            if after.start == before.start && after.end == before.end {
                break; // cannot advance further
            }
            safety += 1;
            if safety > 1_000_000 { // extreme safety cap
                break;
            }
        }
    }

    if !sk.get_prepared_interval().contains(&(epoch as u64)) {
        return Err(format!(
            "Could not prepare secret key for epoch {epoch}. Prepared interval is {:?}",
            sk.get_prepared_interval()
        ));
    }

    // Sign
    let signature = MySigScheme::sign(&sk, epoch, &message)
        .map_err(|e| format!("Signing failed: {e:?}"))?;

    // Wrap signature with epoch and serialize
    let envelope = SigEnvelope::<_> { epoch, signature };
    let env_bytes = encode_to_vec(&envelope, config).map_err(|e| format!("Bincode serialize signature failed: {e}"))?;
    let env_hex = hex_encode(env_bytes);
    write_string_file(&output_path, &env_hex).map_err(|e| format!("Failed to write signature: {e}"))?;

    println!("Signature written to {}", output_path.display());
    Ok(())
}

fn cmd_verify(signature_path: PathBuf, message_str: String, pubkey_path: PathBuf) -> Result<(), String> {
    let config = bincode::config::standard();

    // Load signature envelope (epoch + signature)
    let sig_hex = read_string_file(&signature_path).map_err(|e| format!("Failed to read signature file: {e}"))?;
    let sig_bytes = parse_hex(&sig_hex).map_err(|e| format!("Signature hex decode failed: {e}"))?;
    let (envelope, _): (SigEnvelope<<MySigScheme as SignatureScheme>::Signature>, _) =
        decode_from_slice(&sig_bytes, config).map_err(|e| format!("Bincode decode signature failed: {e}"))?;

    // Load public key
    let pk_hex = read_string_file(&pubkey_path).map_err(|e| format!("Failed to read public key file: {e}"))?;
    let pk_bytes = parse_hex(&pk_hex).map_err(|e| format!("Public key hex decode failed: {e}"))?;
    let (pk, _): (<MySigScheme as SignatureScheme>::PublicKey, _) =
        decode_from_slice(&pk_bytes, config).map_err(|e| format!("Bincode decode public key failed: {e}"))?;

    // Prepare message
    let message = message_to_bytes(&message_str);

    // Verify
    let valid = MySigScheme::verify(&pk, envelope.epoch, &message, &envelope.signature);
    if valid {
        println!("Signature is VALID");
        Ok(())
    } else {
        Err("Signature is INVALID".to_string())
    }
}

fn message_to_bytes(s: &str) -> [u8; MESSAGE_LENGTH] {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = [0u8; MESSAGE_LENGTH];
    out.copy_from_slice(&digest[..MESSAGE_LENGTH]);
    out
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    let no_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex_decode(no_prefix).map_err(|e| e.to_string())
}

fn read_string_file(path: &PathBuf) -> std::io::Result<String> {
    fs::read_to_string(path)
}

fn write_string_file(path: &PathBuf, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let mut f = fs::File::create(path)?;
    f.write_all(content.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}
