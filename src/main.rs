// Corrected crate name: hashashig instead of hash_sig
use hashsig::{
    MESSAGE_LENGTH,
    signature::{SignatureScheme, SignatureSchemeSecretKey,
        // Using a specific scheme instantiation from the library
        generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8,
    },
};
// Re-added Rng trait import
use rand::Rng;


// Define the type alias for the signature scheme for convenience
type MySigScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;

fn main() {
    // This constant is derived from the chosen signature scheme's name (...Lifetime32...)
    const LOG_LIFETIME: usize = 32;

    // Use the new rand API name `rng` instead of the deprecated `thread_rng`
    let mut rng = rand::rng();

    println!("Generating key pair...");
    // Generate keys for the full lifetime, though you could specify a shorter active period
    // Note: Key generation can be slow, especially for large lifetimes.
    // For faster testing/examples, consider using a scheme with a smaller LOG_LIFETIME if available.
    let activation_epoch: usize = 0;
    // Using a smaller number of active epochs for faster key generation in this example
    let num_active_epochs: usize = 1 << 10; // e.g., 1024 epochs instead of full 2^32

    let (pk, mut sk) = MySigScheme::key_gen(&mut rng, activation_epoch, num_active_epochs);
    println!("Key pair generated.");
    println!("Activation interval: {:?}", sk.get_activation_interval());
    println!("Initially prepared interval: {:?}", sk.get_prepared_interval());

    // --- Signing ---
    // Use the new `random` method name as suggested by the deprecation message
    let message: [u8; MESSAGE_LENGTH] = rng.random(); // Generate a random message
    let epoch: u32 = 15; // Choose an epoch within the active range

    println!("\nSigning message at epoch {}...", epoch);

    // Ensure the secret key is prepared for the target epoch
    // In a real application, advance_preparation might happen proactively in the background.
    let mut iterations = 0;
    // Calculate a reasonable safety limit for iterations
    let log_lifetime_half = LOG_LIFETIME / 2;
    // Estimate needed advances based on the tree structure, with a small buffer.
    let max_iterations = if epoch < (1 << log_lifetime_half) {
        1
    } else {
        (epoch >> log_lifetime_half) + 2
    };

    while !sk.get_prepared_interval().contains(&(epoch as u64)) && iterations < max_iterations {
        println!("Advancing key preparation... Current prepared interval: {:?}", sk.get_prepared_interval());
        sk.advance_preparation();
        iterations += 1;
    }

    if !sk.get_prepared_interval().contains(&(epoch as u64)) {
        eprintln!("Error: Could not prepare secret key for epoch {} after {} attempts. Max lifetime might be too small for this epoch.", epoch, iterations);
        eprintln!("Total Lifetime: 2^{}", LOG_LIFETIME);
        eprintln!("Activation: {}-{}", activation_epoch, activation_epoch + num_active_epochs);
        eprintln!("Current Prepared: {:?}", sk.get_prepared_interval());
        return; // Exit if preparation fails
    }
    println!("Secret key prepared for epoch {}. Current prepared interval: {:?}", epoch, sk.get_prepared_interval());


    // Sign the message
    match MySigScheme::sign(&sk, epoch, &message) {
        Ok(signature) => {
            // The signature type from the hashsig crate implements serde::Serialize, so
            // use bincode's serde helper to serialize it (this does not require the
            // `bincode::enc::Encode` trait).
            let config = bincode::config::standard();
            let sig_bytes = bincode::serde::encode_to_vec(&signature, config).expect("Bincode serialize should succeed");
            let sig_size = sig_bytes.len();
            println!("Message signed successfully. Signature serialized size: {} bytes", sig_size);

            // --- Verification ---
            println!("\nVerifying signature...");
            let is_valid = MySigScheme::verify(&pk, epoch, &message, &signature);

            if is_valid {
                println!("Signature is VALID! ✅");
            } else {
                println!("Signature is INVALID! ❌");
            }

            // --- Tamper Test (Optional) ---
            println!("\nTesting verification with a tampered message...");
            let mut tampered_message = message;
            tampered_message[0] = tampered_message[0].wrapping_add(1); // Change the first byte
            let is_tampered_valid = MySigScheme::verify(&pk, epoch, &tampered_message, &signature);

            if !is_tampered_valid {
                println!("Verification correctly FAILED for tampered message. ✅");
            } else {
                println!("Verification INCORRECTLY passed for tampered message! ❌");
            }
        }
        Err(e) => {
            eprintln!("Signing failed: {:?}", e);
        }
    }
}
