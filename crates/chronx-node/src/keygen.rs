/// Dilithium2 keypair generator for child chain namespace owners.
///
/// Usage: cargo run --bin keygen -- --output oracom-oracle-key.json --purpose oracom-oracle
use std::path::PathBuf;

use chronx_crypto::keypair::KeyPair;
use clap::Parser;

#[derive(Parser)]
#[command(name = "keygen", about = "Generate a Dilithium2 keypair")]
struct Args {
    /// Output file path for the keypair JSON.
    #[arg(long)]
    output: PathBuf,

    /// Purpose tag stored in the key file (e.g. "oracom-oracle").
    #[arg(long, default_value = "general")]
    purpose: String,
}

fn main() {
    let args = Args::parse();

    let kp = KeyPair::generate();
    let public_key_hex = hex::encode(&kp.public_key.0);
    let secret_key_hex = hex::encode(kp.secret_key_bytes());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let json = serde_json::json!({
        "public_key": public_key_hex,
        "secret_key": secret_key_hex,
        "account_id": kp.account_id.to_b58(),
        "purpose": args.purpose,
        "created_at": now,
    });

    let pretty = serde_json::to_string_pretty(&json).expect("serialize keypair");
    std::fs::write(&args.output, &pretty).expect("write keypair file");

    println!("Keypair generated:");
    println!("  Account ID: {}", kp.account_id.to_b58());
    println!("  Public key: {}", &public_key_hex[..64]);
    println!("  Purpose:    {}", args.purpose);
    println!("  Saved to:   {}", args.output.display());
    println!("\nSECURITY: Do NOT commit this file to git.");
}
