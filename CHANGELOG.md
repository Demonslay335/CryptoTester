# CryptoTester Changelog
**This program requires .NET Framework 4.8.1 or higher in order to run**

## TODO
- Block mode support for Twofish, Threefish, maybe others (BouncyCastle engines)
- NTRU algorithms

## Known Issues
- Unable to use/import RSA private keys where P and Q are not the same bit length (e.g. RSA-512 with 256-bit P and 257-bit Q) - limitation with Microsoft CSP
- When using a Derive function with the Sosemanuk algorithm, it will always output a 16-byte key

## [1.7.2.0]

### Added
- KCipher-2 stream cipher algorithm
- ZStd compression algorithm
- Compression levels and Password for Compress/Decompress tab
- Split XChaCha20 algorithm into Draft02 and Draft03 versions (initial counter 0x00 and 0x01 respectively) with unit tests
- RSA Calculator and Blob Analyzer can export ASN.1 and PEM explicitly as "PKCS#8 (Legacy)" - an older draft of the spec where `parameters` was OMITTED instead of being explicitly `NULL`
- RSA Calculator will highlight P and Q green if they are prime, or red if they are not prime
- RSA Calculator will automatically calculate D when importing a BCRYPT_RSAPRIVATE_BLOB
- "HC-256 (ECRYPT)" algorithm that matches the ECRYPT version (which was also CryptoPP::HC256's default implementation up to v8.9.0)
- Curve25519 private key (hex string) detection to Key Finder
- "Extra" button for Derive algorithms that need an extra field input
- Derive algorithms for HKDF-MD5, HKDF-SHA1, HKDF-SHA256, and HKDF-SHA512
- Derive algorithms for SipHash-2-4 and SipHash-4-8
- Hash algorithms for Keccak-128, Keccak-224, Keccak-256, Keccak-288, Keccak-384, and Keccak-512
- RNG algorithm JSF (Jenkins Small Fast, 32-bit)
- Keystream Finder tool

### Fixed

- Bruteforce Keys will now skip empty lines in a file
- RSA (Raw) implementation when processing input with leading 0x00 bytes
- Legacy PKCS#8 (ASN.1 or PEM) RSA keys with the missing `parameters` field can now be imported
- Internal construction and export of CryptoAPI blobs when a parameter is one byte less than expected

### Changed
- Reorganized XML, ASN.1, PEM options in various UIs

## [1.7.1.0]

### Added
- Key Finder can now find Base64-encoded XML, ECPoint, and NTRU keys
- RSA Calculator can export ASN.1 and PEM explicitly as PKCS#1 or PKCS#8
- Blob Analyzer can export ASN.1 and PEM explicitly as PKCS#1 or PKCS#8
- GLIBC rand LFSR RNG algorithm
- ARIA block cipher algorithm
- "CryptProtectData (CurrentUser)" and "CryptProtectData (LocalMachine)" encryption algorithms from the CryptoAPI
- ECIES-DHAES (AES-SHA-1) and ECIES-DHAES (Twofish-SHA-1) encryption algorithms
- ECC Validator can generate public/private key pairs for the selected curve
- Tiny-ECDH's incorrect implementation of ECDH as derive functions (K-163, B-163, K-233, B-233, K-283, B-283, K-409, B-409, K-571, and B-571)
- "Reverse Endian (Bytes)", "Reverse Endian (Int32)", and "Reverse Endian (Int64)" context menu options to all hex boxes
- Format "Base64" under Key Options can now accept a base64-encoded ASN.1 key

### Fixed
- Handle text from copy/paste and inputs as ANSI instead of UTF-8
- Base64 encoder in Base Encoder will now give the character and position of an invalid character
- Parsing of PKCS#1 ASN.1/PEM keys
- Encryption/Decryption with RSA and PKCS#1 ASN.1/PEM keys
- Sizing issues with various dialogs and tools
- Index Out of Bounds errors in Key Finder
- "Copy C Array" and "Copy BigNum" context items were enabled even if nothing was selected

### Changed
- Enlarged text fields in Base Encoder
- ECC Validator form can now be horizontally resized
- "Copy C Array" on a hex box will now chunk the array with a new line every 16 bytes

### Removed
- "Reverse Input Bytes" from "Advanced", superseded by new context menu options on hexboxes

## [1.7.0.0]
Key Finder enhancements, new hashes and derive functions, etc.

### Added
- Progress bar to Key Finder
- Curve25519 private key (base64) detection to Key Finder
- secp256k1 and secp521r1 uncompressed ECPoint detection to Key Finder
- ECDH PEM detection to Key Finder
- ASCII for expected output of Bruteforce Keys
- Inputs that accept integers now can use "up" (same as previous "near") and "down" functions to round respectively
	`up(31, 16) == 32`
	`down(31, 16) == 16`
- New Byte Chart: click "Input" or "Output" labels to view respective byte frequencies
- Haval family of hashes (Haval_128, Haval_160, Haval_192, Haval_224, Haval_256) that all accept rounds (3, 4, 5, 8)
- CRC16-ARC and CRC16-MODBUS hashes
- CHC hash (with AES and Blowfish ciphers) from LibTomCrypt
- Button for swapping order of operations for Hash and Derive
- Derive ECDH with secp Koblitz curves: secp160k1, secp192k1, secp224k1, secp256k1
- Derive ECDH with secp Random curves: secp112r1, secp160r1, secp192r1, secp224r1
- Derive ECDH with sect Koblitz curves: sect163k1, sect233k1, sect283k1, sect409k1, sect571k1
- Derive ECDH with sect Random curves: sect163r2, sect233r1, sect283r1, sect409r1, sect571r1
- Derive ECDH with X448
- Derive ECDH with libsecp256k1 (from bitcoin-core)
- Derive GHash (from Galois/Counter Mode)
- Derive HMAC with Blake2b-256, Blake2b-512, Blake2s-128, and Blake2s-256
- Derive Curve25519 can now accept private and public keys as PEM
- Argon2 family of PBKDFs: Argon2i, Argon2d, Argon2id (Interactive, Moderate, Sensitive strengths based on LibSodium's parameters)
- ECDH curves also show their NIST and ANSI X9.62/X9.63 aliases
- ECDH curves can now accept raw little-endian private and public keys (automatically determined)
- Derive ECDH curves can now accept ASN.1 keys (Format Hex or Base64)
- Parsing and validation of BCRYPT_DH_PUBLIC_BLOB, BCRYPT_DH_PRIVATE_BLOB, BCRYPT_DSA_PUBLIC_BLOB, BCRYPT_DSA_PRIVATE_BLOB, BCRYPT_DSA_PUBLIC_BLOB_V2, and BCRYPT_DSA_PRIVATE_BLOB_V2 blobs
- AES-CTR now supports Little Endian for the counter incrementer, and a custom position for the keystream
- OAEP SHA3-224 and OAEP SHA3-384 padding modes for RSA
- OAEP CHC (AES) padding mode for RSA
- RSA algorithm can now accept Encoding Parameter (for OAEP padding modes)
- Better descriptions for padding modes
- Custom Position can now take a hex integer (prefix with "x")
- Threefish (256, 512, and 1024) encryption algorithms
- ECIES-DHAES (XOR-SHA-1) encryption algorithm (matches CryptoPP::ECIES<CryptoPP::ECP>)
- LibSodium CryptoBox algorithms support "Attempt Blind Decryption" (the expected block size of the input is prompted)
- Import ASN.1 blob (or base64 encode) to ECC Validator
- ECC Validator can calculate the Y coordinate of a point when given just the X coordinate and the correct curve
- Blake2s and Blake3 family of hash algorithms
- Blake2b and Blake2s can now take an optional key
- RBT (Residual Block Termination) Block Mode (for AES)

### Changed
- Updated target framework to .NET 4.8.1
- Complete re-write of Key Finder to be more efficient and faster
- Compare tab now draws bytes at an offset that does not exist in the other view as a difference (red)
- Updated dependent libraries
- Organized padding modes more
- Blake2b and Blake2s moved to "Derive" to facilitate accepting a separate hash key

### Fixed
- Null value when selecting an input/output hash and input/output is empty
- ECC Validator could not find a curve if the ECPoint had trailing null bytes
- Input Hash and Input File Info did not update when using the "Move output to input" button
- Key Finder could miss PEMs encoded inside JSON blobs due to escaped newline characters
- Key Finder would stall on false positives for BCRYPT_DH_\* or BCRYPT_DSA_\* blobs
- GCMNoVerify block mode would not encrypt/decrypt the last bytes not divisible by the block size correctly
- Typo with MGF1 padding modes
- Loading a file (via menu or drag-n-drop) to Input on the Compress/Decompress tab would not display the bytes
- Wrong size of IV was generated for Sosemanuk if the IV field was left empty
- ChaCha algorithm threw an index out of bounds error if using a 16-byte key

## [1.6.0.0]
Mega update with **lots** of new features.

### Added
- HC-128 and HC-256 algorithms with unit tests
- ChaCha20Poly1305 and XChaCha20Poly1305 algorithms
- Rabbit algorithm
- "GCMNoVerify" block mode for AES - performs AES-GCM without verifying the tag
- Ability to export RSA keys from RSA Calculator directly to the main window (as any supported format, including raw modulus/exponent)
- Import base64-encoded ASN.1 blob to Blob Analyzer
- CALG_RSA_KEYX to Blob Generator
- Tooltip with hex numbers for Filesize texts
- Length display to input dialog boxes, including hex parsing if expecting bytes
- "Lock Parameters" checkbox to not overwrite Offset/Length when loading files
- secp128r1, secp256r1, secp384r1, and secp521r1 ECDH key exchanges as derive functions
- HChaCha20 as derive function
- Option to view hash of input
- Option to Verify for encrypt/decrypt - e.g. verifying an ECDSA signature of the output
- Operations -> Attempt Blind Decryption - crawls the Input and attempts to decrypt any valid block (only supports RSA algorithm currently)
- Detection of base64-encoded PEM and base64-ROT13-encoded PEM keys to Key Finder
- Detection of base64-encoded ASN.1 keys to Key Finder
- RSA Calculator can now also calculate D using [N, P|Q, E], and fills the missing variables
- Input -> Integer for accepting an integer (converts to bytes)
- "ECC Validator" tool - supports secp\*k1 and secp\*r1 curve families, or custom parameters
- ECPoint import and export to ECC Validator
- PEM import to ECC Validator - will also automatically load curve parameters (if OID is defined)
- CNG Blob import to ECC Validator - will also automatically load curve parameters (if valid magic)
- "Scarab Ransomware" Base64 charset preset to Base Encoder
- Custom round and position support for ChaCha20 (RFC-7539) algorithm
- Progress bar for "Bruteforce Algorithm" operation
- Input IV from Base64 (Advanced -> IV)
- "Recover IV From Plaintext" (Advanced -> IV), recovers the IV by XORing the ciphertext (Output) and your known plaintext
- "Chunk Viewer" tool - allows viewing input as per-block chunks, with optional XOR filter
- "Skip Chars" to RNG Tester
- Custom constant support for XXTEA algorithm
- ASN.1 format support to Bruteforce Keys tool
- "Reset Length" button to reset the File Options -> Length to the input's length
- SHA-512/224 and SHA-512/256 hashes
- OAEP_SHA512_224, OAEP_SHA512_256, OAEP_SHA3_256, and OAEP_SHA3_512 padding schemes (for RSA)
- OAEP_SHA256_MFG1_SHA384, OAEP_SHA256_MFG1_SHA512, and OAEP_SHA384_MFG1_SHA512 padding schemes (for RSA)
- Support for RSA keys > 4096 bit
- Support for ECPoint formatted or raw byte private/public keys when using Elliptic Derive algorithms
- SHA3, and Blake2b families of hash algorithms
- XXHash and Murmur3 families of hash algorithms
- Adler32 checksum and BlackMatter's custom hash algorithms
- "Copy C Array" option for hex boxes (context menu or Ctrl+Shift+C)
- "Copy BigNum" option for hex boxes (context menu)
- "Chunks" mode for encrypt input bytes - define number of bytes to take and skip to encrypt/decrypt bytes in chunks (also works with "Splice Remaining Bytes" to interweave untouched bytes)
- aPLib compression algorithm (only decompression supported for now)
- "Reverse Input" button to Base Encoder
- "LibSodium CryptoBox Easy" (crypto_box_easy / crypto_box_open_easy) algorithm - expects private_key|public_key for Key currently
- "LibSodium CryptoBox Seal" (crypto_box_seal / crypto_box_seal_open) algorithm
- Detection of <RSAKeyPair> XML keys to Key Finder
- Detection of some NTRU keys (libntru format EES401EP2 and EES587EP1) to Key Finder
- Textbox for seed with hashes that support one (default is provided otherwise)
- Real HMAC_MD5 and HMAC_SHA\* derive algorithms
- Operation -> "Generate Keystream" on the Encrypt/Decrypt tab can now generate a direct keystream to file (encrypt 0x00 bytes) for stream ciphers
- RSA algorithm will now automatically decrypt in sequential chunks if total length is divisible by the modulus bitlength

### Changed
- Updated target framework to .NET 4.7.2
- Updated dependent libraries
- RSA Calculator form now allows resizing
- Changed output hash to update when dropdown changes
- Expanded size of Algorithm, Hash, Derive, and Padding dropdowns to view full text better
- Grouped Hashes for easier finding of algorithm
- Grouped Derive functions for easier finding of algorithm
- Grouped Padding modes for easier finding of algorithm
- Renamed HMACSHA\*, to respective PBDKF2\* derive algorithms

### Fixed
- Fixed Sosemanuk unit test
- Fixed Sosemanuk to accept derived keys
- Fixed File Options -> Length to assume relative to end of input if parsed value is negative
- Fixed output endianness of RSA Raw algorithm
- Fixed hex output when generating a key in RSA Calculator
- Fixed being able to export a blank/broken key when first opening RSA Calculator
- Fixed XOR Analysis in Compare tab when not the whole file was encrypted
- Fixed "To Hex" conversion in Hex Integer Converter when using commas and spaces
- Fixed Bruteforce Algorithm operation selecting Custom padding mode (caused popup on each iteration)
- Moved Bruteforce Algorithm operation to a background thread for better performance and UI responsiveness
- Fixed export of key in RSA Calculator where N bitlength may be -1 from valid RSA bit lengths (e.g. 0x3FF or 0x7FF)
- Fixed Cut operation on hex views
- Fixed Base Encoder resetting dropdowns when it was opened multiple times
- Fixed Key Finder to stop async task if dialog is closed
- Fixed display of a repairable CNG key blob in Key Finder
- Fixed unhelpful message on bad derive key length
- Fixed compression under Compress/Decompress tab
- Fixed crash in Key Finder with displaying an invalid CNG blob when it is a false-positive from the magic header
- Fixed mis-reporting of key count in Key Finder when a false-positive is found (and suppressed)
- Fixed bug with Reverse Input Bytes when input was empty
- Fixed finding ASN.1 sequences with certain lengths in Key Finder
- Fixed duplicate keys found with nested ASN.1 sequences in Key Finder
- Fixed vague error with TEA algorithm and keys < 16 bytes (TEA exclusively will only use 16 bytes of any given key)
- Fixed Little Endian mode for TEA algorithm when using an IV
- Fixed "Flip Endianness" in RSA Calculator when value went negative
- Fixed enumerating folder of CryptoAPI blobs in Bruteforce Keys tool
- Fixed "Non NULL" expectation in Bruteforce Keys tool
- Fixed RSA decryption of CryptoAPI-encrypted ciphertext when using OAEP_SHA256, OAEP_SHA384, or OAEP_SHA512 padding
- Fixed RSA key PEM parsing when encoded newlines are present

### Removed
- Removed ECDH-ED25519 derive (misunderstanding, not actually a ECDH key exchange algorithm - it is an EdDSA signature algorithm)

## [1.5.0.0]

### Added
- Key Finder: Detection of truncated base64 keys
- Key Finder: Added support for finding ASN.1 key blobs
- Key Finder: Added support for finding ASN.1 key blobs as ASCII strings
- Key Finder: Added support for finding raw public modulus and exponent as ASCII strings
- Added custom round and constant support for ChaCha20 algorithm
- Added "Edit Title" to window context menu - changes the title of the window
- Added AES GCM block mode (GCM tag is expected to be appended to the ciphertext)
- Added Custom padding mode (enter any single byte to use as padding)
- Added option to compute hash of output during encrypt/decrypt
- Added support for PEM private RSA PKCS#8 keys
- Added ECDH-secp256k1, ECDH-ED25519, and Curve25119 key exchanges as derive functions (will ask for Other's Public Key)
- Added ability for algorithms to change UI labels as appropriate (e.g. "Raw RSA" uses "Modulus" and "Exponent" instead of "Key" and "IV")
- Added ability for algorithms to enable/disable supported key format radio buttons
- Added ability for algorithms to accept no key (e.g. ROT13, CertUtilEncode)
- Added AutoIT (MT) RNG algorithm
- Added checkbox to toggle syncronized scrolling of hex views
- Added support for "Drop N" to RC4 algorithm (parses as an integer string)
- Added coloring of 0x00 bytes in hex views (dark gray)
- Added Sosemanuk algorithm and unit test
- Added CRC32 and MD4 hash algorithms
- Added String Encoder tool - convert between ASCII/UTF8/UTF16 strings and bytes
- Added export of public/private keys to clipboard in RSA Calculator
- Added ASN.1 export to RSA Calculator
- Added OAEP_SHA1, OAEP_SHA256, OAEP_384, and OAEP_512 padding modes (for RSA)
- Added custom "Position" (Advanced -> Custom) to manually set the stream position used in Salsa20/ChaCha20
- Added custom "Matrix" (Advanced -> Custom) to manually set the initial state used in Salsa20/ChaCha20 (parses the key, nonce, constant, and stream position)
- Added support for CNG RSA key blobs in Blob Analyzer, RSA Calculator, and for encrypt/decrypt
- Added "Sum XOR" stream cipher - a running sum is created from each byte of the key and XOR'd with the plaintext (i.e. seen in MountLocker ransomware)
- Added "RC4 Custom Sbox" algorithm (parses as an integer string)
- Added checkbox for appending Input text or base64
- Added ability to reverse input bytes (Advanced -> Reverse Input Bytes)
- Added support for offset < 0 to Generate Keystream operation (syncs end of file relatively based on smaller file)
- RSA Calculator now calculates N from P and Q if not provided

### Changed
- Minor updates to library dependencies

### Fixed
- Fixed AES CFB mode decryption for inputs not % blocksize (overcomes bug in .NET provider)
- Fixed ECB mode to ignore IV if provided
- Fixed HiddenTear preset
- Fixed Generate Keystream operation using offset > 0
- Fixed support for ASN.1 private RSA PKCS#1 keys that have an outer sequence
- Fixed support for ASN.1 public RSA PKCS#1 keys that have an inner sequence
- Fixed import/use of PEMs with missing positive byte marker on parameters
- Fixed crash on short key found in Bruteforce Keys tool
- Fixed Base Encoder to accept larger inputs
- Fixed RSA key verification to allow other solutions for D (was causing verification to fail on legitimate keys)
- Fixed hex views scrolling two lines instead of one per scroll click
- Fixed hex views synced scrolling with scrollbar and keys
- Fixed File Option -> Offset to assume relative to end of input if parsed value is negative
- Fixed duplicate output from Key Finder when it was opened and closed multiple times
- Fixed duplicate runs of Bruteforce Keys when it was opened and closed multiple times
- Fixed XTS block mode to actually use IV (as Key2)

### Removed
- Removed ECB analysis in Compare (wasn't working correctly)
	- Replaced with Hash Analysis (checks for digest of Original in Encrypted)

## [1.4.0.3]

### Fixed
- Blob parsing (regression from 1.4.0.2 with internal endianness changes)

## [1.4.0.2]
Major changes to the hex views.

### Hex Views

#### Added
- Esc (cancel selection) shortcut
- Home (go to beginning of current row) shortcut
- End (go to end of current row) shortcut
- Auto ASCII/UTF-16 conversion when selecting

#### Changed
- Changed shortcuts to go to very beginning (Ctrl+Home) and very end of file (Ctrl+End)

#### Fixed
- Moving selection when start of selection is last byte
- Page up when exactly one page down from byte 0
- Clearing selection when pressing shift+up and start of selection is byte 0
- Clearing selection when pressing shift+down and start of selection is last byte
- Shift+up deselecting two rows
- Release selection when pressing Home on byte 0 and End on last byte

### Added
- Support for finding cryptoblobs as ASCII strings in Key Finder
- Esc (close) shortcut for all dialogs
- "Flip Endian" tool to Blob Analyzer and RSA Calculator
- Drag-n-drop file support to IV textbox
- "Custom Constant" (Advanced) to manually set the constant bytes used in Salsa20 (overrides default sigma/tau)
- Explicit OAEP padding to dropdown for RSA to be more clear (previously used OAEP if anything but None)
- AES XTS block mode
- HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512 derive functions
- RSA (Raw) algorithm - provide d or e as Key, n as IV

### Changed
- Grouped algorithms by cipher type to make long dropdown easier to find an algorithm, now also shows full proper names for algorithms
- Redesigned Bruteforce Keys tool to accept a byte count (e.g. key file with raw byte keys appended)

### Fixed
- Fixed Desert.jpg resource
- Detection of PEM keys without newlines in Key Finder
- Fixed RC2, RC5, and RC6 algorithms to actually act like block ciphers - accept block mode, padding mode, and IV
- RC4 keysize for CryptDeriveKey
- RSA Calculator to parse hex like other inputs (ignore spaces, colons, commas, etc.)
- Progress bar of Bruteforce Keys tool

## [1.4.0.1]

### Added
- Embedded Chrysanthemum.jpg and Desert.jpg (Windows 7 sample pictures) as input options
- Copy/paste for hex boxes in Compare tab
- Ctrl+F (find) shortcut for all hex views
- Ctrl+G (goto) shortcut for all hex views
- Ctrl+O (Open File) and Ctrl+S (Save Output) shortcuts
- Selection length display to hex views
- Auto WORD/DWORD/QWORD conversion when selecting in hex views
- Some menu icons!
- Enabled Compress button on Compress tab (note some algorithms are buggy, work in progress)
- Enabled input menu for Compare tab (fills as Original)

### Changed
- Removed Input -> Raw Bytes (superceded by Paste option)

### Fixed
- Swap button in Compare tab
- Block mode, padding mode, and IV for Serpent algorithm

## [1.4.0.0]

### Added
- Entropy calculation for string outputs in RNG Tester
- Seed, length, and modulus in RNG Tester now accepts expressions (e.g. x10)
- Modulus for string outputs in RNG Tester (as algorithm permits)
- Decoded views for Compare and Compress/Decompress tab - click on offset bar
- New padding modes - Spaces (' ') and Ascii Zeros ('0') (used in Python crypto alot for some reason)
- CertUtilEncode algorithm (certutil.exe -encode/-decode)
- ASN.1 key usage for encrypt/decrypt
- Addition/Subtraction encryption algorithms
- Addition/Subtraction detection to Compare files tab
- Button to move output to input in Encrypt tab
- Button to swap original/encrypted in Compare files tab
- Search bytes buttons to all hex views
- Coloring of Newline sequence characters (purple) in hex editors

### Changed
- Minor version updates to library dependencies
- Code rearranging/cleanup

### Fixed
- SymmetricAlgorithm's bug of not removing zero (0x00) padding
- Crash when clicking decode view with empty hex
- Crash when trying to open a file already open by another program
- Key length not populated in Blob Generator on load
- Accepting manual input of key length in Blob Generator

## [1.3.0.9]

### Added
- ASN.1 import and export to Blob Analyzer
- Basic XOR encryption detection to Compare files tab
- Ctrl+A (select all) shortcut for all hex edit views
- Base58 and Base58Check encodings to Base Encoder
- Misty1 and Kasumi encryption algorithms (with unit tests)
- Fermet encryption scheme (with unit test)
- "Enter Text" for input
- Iterations for Hash

### Fixed
- Error with converting DWORDs
- Memory access errors when copy/paste contents to other hex editor programs (HxD in particular)

## [1.3.0.8]

### Added
- File offset/length now accept expressions, including variables for the file length; e.g. "length - x10"
	x<number> = interpret number as hexidecimal
		Example: x10 = 16
	hex(<expression) = intepret expression as hexidecimal
		Example: hex(10) = 16
		Alias: h()
	length = file length
		Alias: len, filelen, filelength, filesize, size
	block = blocksize of current selected algorithm
		Alias: b
	nearest(v, n) = round v to nearest n
		Example: nearest(60, 16) = 64
		Alias: near, n
- "Sequential Bytes" input - automatically generates 0x00 - 0xFF up to given limit
- Input "Zeroes" and "Sequential Bytes" can also accept above expressions
- Input/output length display to Base Encoder
- Detection of ROT13-encoded keys to Key Finder
- Detection of damaged (but repairable) BLOBs to Key Finder
- Blob Generator tool to Blob Analyzer - generate a random cryptoblob with specified parameters
- "Bruteforce Keys" tool - attempts decryption using a key list and the specified encryption parameters of the main window
- "Splice Remaining Bytes" checkbox to splice bytes before/after selected offset to the output
- Base64 detection for dragging key file into "Key" textbox
- Drag-and-drop file into Blob Analyzer (auto-detects input type)
- Export to clipboard for base64, PEM, and XML (BlobAnalyzer) - resorted menu options

### Fixed
- Accepting newlines in Base Encoder
- "PHP mt_rand" and "PHP 7.1 mt_rand" RNG algorithms (RNG Tester)

## [1.3.0.7]

### Added
- Decoded view for original/encrypted bytes - click on offset bar
- OpenSSL-compatible Derives (EVP_BytesToKey) - MD5 (pre OpenSSL 1.1.0c), and SHA256 (post OpenSSL 1.1.0c)
- Preset feature - presets common crypto schemes
- Presets for HiddenTear and OpenSSL

### Fixed
- Fallback for incorrectly declared PKCS#8 PEM keys
- Detection of SIMPLEBLOBs in Key Finder
- Acceptance of keys with new lines (e.g. PEM) for the main window
- Tweaked input fields expecting hex byte to ignore tabs, carriage returns, "h" prefixes, and bracket/braces

## [1.3.0.6]

### Added
- Added basic support for CNG blobs in Blob Analyzer and Key Finder
- Added generation of example RSA keys (cannot guarantee cryptographically safe!)
- RSA Calculator can now calculate primes (p and q) if given public and private exponents and modulus (n, e, and d)
- Blob Analyzer repair option can fix private RSA key blobs with corrupted primes if above (n, e, d) variables are valid

### Fixed
- XSalsa20 algorithm

## [1.3.0.5]

### Added
- Repair option for private RSA key blobs (Blob Analyzer)
- Test vectors for Blowfish algorithm
- C++ MT19937 (MT) RNG algorithm

### Changed
- Updated dependant libraries

### Fixed
- Bug with DeriveKey hashes when used with AES-256 (keysize is respected vs blocksize)

## [1.3.0.4]

### Added
- Extraction of some common PEM stubs (without BEGIN/END markers) to Key Finder
- Generate Keystream (XORs two files from Compare tab, Operations -> Generate Keystream)
- Bruteforce Algorithm (tries all algorithm, hash, block mode, padding mode combination with given key, Operations -> Bruteforce Algorithm)

### Fixed
- Capture of PEM strings that are chunked in Key Finder
- Parsing of UTF16 strings in Key Finder
- Max length of characters allowed on input forms
- Tweaked input fields expecting hex bytes to ignore "-"
- Pasting of hex strings in main window
- Bug with DeriveKey hashes using SHA-2 family of hashes
- Bug with DeriveKey hashes when used with AES-128

## [1.3.0.3]

### Added
- ChaCha20 (IETF) algorithm
- Little Endian option (currently only flips byte order for TEA/XTEA, Advanced -> Little Endian)
- Option to add an IV from UTF8 text (Advanced -> IV -> Enter Text IV)
- RSA Broadcast Attack tool (Cracking -> RSA -> RSA Broadcast Attack, only supports e=3 currently)
- XOR Attack tool (Cracking -> XOR -> XOR Attack)

### Changed
- Organized IV related options (Advanced -> IV)
- Tweaked any input field that expects hex bytes to ignore "0x" prefixes and commas (make pasting from code easier)

### Fixed
- Bug with syncing hex editor with byte stream used for encrypting when saving

## [1.3.0.2]

### Added
- PasswordDeriveBytes for key generation
- Option to enable/disable RFC2898/Password Derive functions from auto deriving the IV (Advanced -> Auto Derive IV)
- PKCS#1 PEM parsing ("BEGIN RSA PUBLIC KEY")
- UTF-16/wide string detection to Key Finder
- Progress updates to Key Finder
- String input for XML to Blob Analyzer
- New input for strings that accepts newlines (e.g. PEM or Base64 input of Blob Analyzer)

### Fixed
- Auto-generation of Salsa20 IV
- Enabling of Encrypt/Decrypt buttons when pasting or typing in input hexbox
- Long error messages that would break the status label of windows

## [1.3.0.1]

### Added
- Added coloring of ASCII characters (orange) in hex editors
- Added "Search Bytes" option (Operations)
- Added modulus for RNG Tester

### Changed
- Tweaked tool menu options

### Fixed
- Possible crash with comparing small files
- Filesize difference on drag-and-drop comparing
- Paste from context menu for hex editor
- File info stats for manually edited hex

## [1.3.0.0]

### Added
- Paste function to input (left hex editor in Encrypt/Decrypt tab)
- Display of generated key (click on the length)
- Finding PGP public and private keys in Key Finder
- "SharpAESCrypt" algorithm

### Changed
- Updated target framework to .NET 4.6.1
- Updated several internal libraries
- Moved "Get IV From Input" to Advanced toolstrip (removed button)
- Removed restriction of PE files for Key Finder (allow searching of binary dumps, etc)

### Fixed
- Copy function in hex editors
- Possible crash on Key Finder
- A few false positives in Key Finder
- GUI fixes for Display Bytes

## [1.2.0.6]

### Added
- Base Encoder utility (Tools -> Base Encoder)
- Unit testing for RNG algorithms (automatically run on use in RNG Tester)
- Full validation of BLOBs
- Option to export RSA key as public or private key (RSA Calculator)
- BSD libc rand (LCG) RNG algorithm
- Java.util.Random (LCG) RNG algorithm
- Display of rounds used when encrypting/decrypting (on supported algorithms)

### Fixed
- RSA decryption of data if it was originally encrypted by a CSP provider
- Random string generation with PowerShell and PowerShell5 RNG algorithms (to mimic -InputObject processing)
- Parsing of BLOBs if extra bytes are added in Blob Analyzer
- Export of BLOBs in Blob Analyzer to respect the proper output based on blob type
- GUI fixes for RNG Tester

## [1.2.0.5]

### Added
- Base64 input for Encrypt/Decrypt tab
- Accessing RSA Calculator from main window
- Test vectors for IDEA algorithm
- Additional error handling

### Fixed
- Block mode and padding support for some algorithms
- Default IV size for some algorithms
- Delphi (LCG) RNG algorithm
- Changing base for RSA Calculator variables

## [1.2.0.4]

### Added
- RSA Calculator utility to Blob Analyzer (Tools -> RSA Calculator)
- Compare blob analysis now looks for any kind of BLOB
- Configurable Rounds for applicable algorithms (Advanced -> Rounds)
- RC5 (16-bit wordsize) algorithm

### Fixed
- Corrected RC5 wordsize wording (blocksize != wordsize)

### Changed
- Removed "Salsa20_8" and "Salsa20_12" algorithms in favor of using Rounds config

## [1.2.0.3]

### Added
- Rijndael (192-bit blocksize) algorithm
- Rijndael (256-bit blocksize) algorithm
- RC5 (64-bit wordsize) algorithm
- Detection of any kind of BLOB to Key Finder
- Output of the bitlength for RSA keys found as PEM/XML/Base64 in Key Finder
- Button to automatically extract first (blocksize) of input as IV

## [1.2.0.2]

### Fixed
- Parsing of SIMPLEBLOBs

### Changed
- Tweaks to Key Finder display

## [1.2.0.1]

### Added
- Base64 decode to Blob Analyzer
- Key Finder utility

### Changed
- Internal re-write of BLOB parsing

## [1.2.0.0]
First public release
