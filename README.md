# hash-sig-example

A small Rust CLI for hash-based signatures (Poseidon top-level, lifetime 2^32).

The CLI can generate a keypair, sign messages (the message is SHA-256 hashed to 32 bytes), and verify signatures. Keys and signatures are serialized with `bincode` and hex-encoded for easy storage and transport.

## Requirements

- Rust toolchain (stable) and `cargo`
- Development tested on macOS, but should work on other platforms supported by Rust

## Build

From the project root:

```bash
cargo build --release
```

Or run directly without building the release binary:

```bash
cargo run --release -- <subcommand> [args]
```

The release binary is produced at `target/release/hash-sig-example`.

## Usage

The CLI exposes three main subcommands: `generate`, `sign`, and `verify`.

Generate a keypair

```bash
# creates `pubkey.hex` and `secret.hex` in the specified output directory (e.g. `keystore/`)
cargo run --release -- generate --output keystore --activation-epoch 0 --num-active-epochs 1024
```

Sign a message

```bash
cargo run --release -- sign --key keystore/secret.hex --message "Hello world" --epoch 0 --output signature.hex
```

Verify a signature

```bash
cargo run --release -- verify --signature signature.hex --message "Hello world" --pubkey keystore/pubkey.hex
```

Notes about the CLI flags

- `--output` for `generate` is the directory where `pubkey.hex` and `secret.hex` will be written.
- `--key` and `--pubkey` expect hex files (optionally with a leading `0x` which is ignored).
- `--message` is an arbitrary UTF-8 string; the CLI hashes it with SHA-256 and uses the first 32 bytes of the digest as the message payload.
- `--epoch` is the epoch at which to sign/verify.

## File formats

- `pubkey.hex` / `secret.hex`: hex-encoded `bincode` serialization of the public/secret key values.
- Signature file (e.g. `signature.hex`): hex-encoded `bincode` serialization of a small envelope containing:
  - `epoch` (u32)
  - `signature` (scheme-specific)

All files are plain hex text (a trailing newline is allowed and produced by the CLI). The CLI trims an optional `0x` prefix when reading hex files.

## Implementation notes

- Messages are hashed with SHA-256 and truncated/padded to the scheme's `MESSAGE_LENGTH`.
- Signing will fail if the requested epoch is outside the key's activation interval or the secret key cannot be prepared for that epoch.
- The project bundles a `vendor/hash-sig/` directory with related code used by the example.

## Troubleshooting

- If key generation is slow, try reducing `--num-active-epochs` for local experimentation; production parameters will likely be much larger.
- If you see bincode/serialization errors, verify the file contents are valid hex and were produced by this CLI (mixing different scheme versions will cause decode errors).

## License

See the project `Cargo.toml` and the `vendor/hash-sig/README.md` for licensing details.

