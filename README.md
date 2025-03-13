
# secoxide

**Production-Optimized - Rainbow Table Version**

secoxide is a Rust-based command-line tool designed to recover an Exodus wallet’s seed (or secret) from encrypted `.seco` files. By leveraging a rainbow table approach and concurrent processing, secoxide efficiently tests candidate passwords from a provided wordlist, decrypting files using robust cryptography.

## Overview

secoxide operates by:
- **Parsing** the `.seco` file header to extract cryptographic parameters.
- **Deriving Keys** from candidate passwords using scrypt.
- **Decrypting** the ciphertext with AES-256-GCM.
- **Building a Rainbow Table** in parallel for rapid password verification.
- **Processing Multiple Files Concurrently** with asynchronous I/O and parallel processing.

## File Format (Hypothetical)

Each `.seco` file adheres to the following structure:
- **Magic:** 4 bytes (`"SECO"`)
- **Version:** 1 byte (expected values: 0 or 1)
- **Salt Length:** 1 byte (e.g., 16)
- **Salt:** Variable (as specified by the salt length)
- **IV Length:** 1 byte (e.g., 12)
- **IV:** Variable (as specified by the IV length)
- **Tag Length:** 1 byte (e.g., 16)
- **Tag:** Variable (as specified by the tag length)
- **Ciphertext:** All remaining bytes in the file

## How It Works

1. **File Parsing:**  
   Reads the file, checks for the `"SECO"` magic bytes, and extracts version, salt, IV, tag, and ciphertext.

2. **Key Derivation:**  
   Uses scrypt (with fixed parameters: N=16384, r=8, p=1) to derive a 32-byte key from each candidate password and the extracted salt.

3. **Decryption:**  
   Decrypts the ciphertext using AES-256-GCM. The ciphertext is combined with the authentication tag to verify integrity.

4. **Rainbow Table Construction:**  
   Generates a mapping of derived key hex values to candidate passwords in parallel, which speeds up the process of finding the correct password.

5. **Concurrent Processing:**  
   Processes multiple `.seco` files concurrently using Tokio for asynchronous file I/O and Rayon for parallel password verification.

## Tech Stack

- **Rust:** High-performance systems programming language.
- **Tokio:** Asynchronous runtime for handling non-blocking I/O.
- **Rayon:** Library for data parallelism, used for parallel processing of candidate passwords.
- **Clap:** Command-line argument parsing.
- **scrypt:** Password-based key derivation function.
- **AES-256-GCM:** Authenticated decryption algorithm.
- **Log & Env Logger:** For detailed logging and debugging.
- **Indicatif:** Provides real-time progress bars in the terminal.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/secoxide.git
   cd secoxide
   ```

2. **Build the Project:**

   ```bash
   cargo build --release
   ```

## Usage

After building, you can run secoxide using the following command:

```bash
./target/release/secoxide --directory /path/to/seco_files --wordlist /path/to/wordlist.txt --verbose
```

- `--directory`: Path to the directory containing `.seco` files.
- `--wordlist`: Path to a text file with one candidate password per line.
- `--verbose`: Enables detailed logging and progress output.

## Disclaimer

This code is provided as an example. Ensure that you audit and test it thoroughly before using it in any production environment.

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request for improvements.

## License

This project is licensed under the [MIT License](LICENSE).

