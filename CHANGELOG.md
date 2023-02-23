# CryptoTester Changelog
**This program requires .NET Framework 4.7.2 or higher in order to run**

## [1.6.0.0]
+ Updated target framework to .NET 4.7.2
+ Updated dependent libraries
+ Added HC-128 and HC-256 algorithms with unit tests
+ Added ChaCha20Poly1305 and XChaCha20Poly1305 algorithms
+ Added Rabbit algorithm
+ Added "GCMNoVerify" block mode for AES - performs AES-GCM without verifying the tag
+ Added ability to export RSA keys from RSA Calculator directly to the main window (as any supported format, including raw modulus/exponent)
+ Added import base64-encoded ASN.1 blob to Blob Analyzer
+ Added CALG_RSA_KEYX to Blob Generator
+ Added tooltip with hex numbers for Filesize texts
+ Added length display to input dialog boxes, including hex parsing if expecting bytes
+ Added "Lock Parameters" checkbox to not overwrite Offset/Length when loading files
+ Added secp128r1, secp256r1, secp384r1, and secp521r1 ECDH key exchanges as derive functions
+ Added HChaCha20 as derive function
+ Added option to view hash of input
+ Added option to Verify for encrypt/decrypt - e.g. verifying an ECDSA signature of the output
+ Added Operations -> Attempt Blind Decryption - crawls the Input and attempts to decrypt any valid block (only supports RSA algorithm currently)
+ Added detection of base64-encoded PEM and base64-ROT13-encoded PEM keys to Key Finder
+ Added detection of base64-encoded ASN.1 keys to Key Finder
+ RSA Calculator can now also calculate D using [N, P|Q, E], and fills the missing variables
+ Added Input -> Integer for accepting an integer (converts to bytes)
+ Added "ECC Validator" tool - supports secp*k1 and secp*r1 curve families, or custom parameters
+ Added ECPoint import and export to ECC Validator
+ Added PEM import to ECC Validator - will also automatically load curve parameters (if OID is defined)
+ Added CNG Blob import to ECC Validator - will also automatically load curve parameters (if valid magic)
+ Added "Scarab Ransomware" Base64 charset preset to Base Encoder
+ Added custom round and position support for ChaCha20 (RFC-7539) algorithm
+ Added progress bar for "Bruteforce Algorithm" operation
+ Added input IV from Base64 (Advanced -> IV)
+ Added "Recover IV From Plaintext" (Advanced -> IV), recovers the IV by XORing the ciphertext (Output) and your known plaintext
+ Added "Chunk Viewer" tool - allows viewing input as per-block chunks, with optional XOR filter
+ Added "Skip Chars" to RNG Tester
+ Added custom constant support for XXTEA algorithm
+ Added ASN.1 format support to Bruteforce Keys tool
+ Added "Reset Length" button to reset the File Options -> Length to the input's length
+ Added SHA-512/224 and SHA-512/256 hashes
+ Added OAEP_SHA512_224, OAEP_SHA512_256, OAEP_SHA3_256, and OAEP_SHA3_512 padding schemes (for RSA)
+ Added OAEP_SHA256_MFG1_SHA384, OAEP_SHA256_MFG1_SHA512, and OAEP_SHA384_MFG1_SHA512 padding schemes (for RSA)
+ Added support for RSA keys > 4096 bit
+ Added support for ECPoint formatted or raw byte private/public keys when using Elliptic Derive algorithms
+ Added SHA3 and Blake2b families of hash algorithms
+ Added XXHash and Murmur3 families of hash algorithms
+ Added Adler32 checksum and BlackMatter's custom hash algorithms
+ Added "Copy C Array" option for hex boxes (context menu or Ctrl+Shift+C)
+ Added "Copy BigNum" option for hex boxes (context menu)
+ Added "Chunks" mode for encrypt input bytes - define number of bytes to take and skip to encrypt/decrypt bytes in chunks (also works with "Splice Remaining Bytes" to interweave untouched bytes)
+ Added aPLib compression algorithm (only decompression supported for now)
+ Added "Reverse Input" button to Base Encoder
+ Added "LibSodium CryptoBox Easy" (crypto_box_easy / crypto_box_open_easy) algorithm - expects private_key|public_key for Key currently
+ Added "LibSodium CryptoBox Seal" (crypto_box_seal / crypto_box_seal_open) algorithm
+ Added detection of <RSAKeyPair> XML keys to Key Finder
+ Added detection of some NTRU keys (libntru format EES401EP2 and EES587EP1) to Key Finder
+ Added textbox for seed with hashes that support one (default is provided otherwise)
+ Fixed Sosemanuk unit test
+ Fixed Sosemanuk to accept derived keys
+ Fixed File Options -> Length to assume relative to end of input if parsed value is negative
+ Fixed output endianness of RSA Raw algorithm
+ Fixed hex output when generating a key in RSA Calculator
+ Fixed being able to export a blank/broken key when first opening RSA Calculator
+ Fixed XOR Analysis in Compare tab when not the whole file was encrypted
+ Fixed "To Hex" conversion in Hex Integer Converter when using commas and spaces
+ Fixed Bruteforce Algorithm operation selecting Custom padding mode (caused popup on each iteration)
+ Moved Bruteforce Algorithm operation to a background thread for better performance and UI responsiveness
+ Fixed export of key in RSA Calculator where N bitlength may be -1 from valid RSA bit lengths (e.g. 0x3FF or 0x7FF)
+ Fixed Cut operation on hex views
+ Fixed Base Encoder resetting dropdowns when it was opened multiple times
+ Fixed Key Finder to stop async task if dialog is closed
+ Fixed display of a repairable CNG key blob in Key Finder
+ Fixed unhelpful message on bad derive key length
+ Fixed compression under Compress/Decompress tab
+ Fixed crash in Key Finder with displaying an invalid CNG blob when it is a false-positive from the magic header
+ Fixed mis-reporting of key count in Key Finder when a false-positive is found (and suppressed)
+ Fixed bug with Reverse Input Bytes when input was empty
+ Fixed finding ASN.1 sequences with certain lengths in Key Finder
+ Fixed duplicate keys found with nested ASN.1 sequences in Key Finder
+ Fixed vague error with TEA algorithm and keys < 16 bytes (TEA exclusively will only use 16 bytes of any given key)
+ Fixed Little Endian mode for TEA algorithm when using an IV
+ Fixed "Flip Endianness" in RSA Calculator when value went negative
+ Fixed enumerating folder of CryptoAPI blobs in Bruteforce Keys tool
+ Fixed "Non NULL" expectation in Bruteforce Keys tool
+ Fixed RSA decryption of CryptoAPI-encrypted ciphertext when using OAEP_SHA256, OAEP_SHA384, or OAEP_SHA512 padding
+ Fixed RSA key PEM parsing when encoded newlines are present
+ Changed RSA Calculator form to allow for resizing
+ Changed output hash to update when dropdown changes
+ Expanded size of Algorithm, Hash, Derive, and Padding dropdowns to view full text better
+ Grouped Hashes for easier finding of algorithm
+ Grouped Derive functions for easier finding of algorithm
+ Grouped Padding modes for easier finding of algorithm
+ Renamed HMACSHA*, to respective PBDKF2* derive algorithms
+ Added real HMAC_MD5 and HMAC_SHA* derive algorithms
+ Operation -> "Generate Keystream" on the Encrypt/Decrypt tab can now generate a direct keystream to file (encrypt 0x00 bytes) for stream ciphers
+ RSA algorithm will now automatically decrypt in sequential chunks if total length is divisible by the modulus bitlength
- Removed ECDH-ED25519 derive (misunderstanding, not actually a ECDH key exchange algorithm - it is an EdDSA signature algorithm)

## [1.5.0.0]
+ Key Finder:
	+ Added detection of truncated base64 keys
	+ Added support for finding ASN.1 key blobs
	+ Added support for finding ASN.1 key blobs as ASCII strings
	+ Added support for finding raw public modulus and exponent as ASCII strings
+ Added custom round and constant support for ChaCha20 algorithm
+ Added "Edit Title" to window context menu - changes the title of the window
+ Added AES GCM block mode (GCM tag is expected to be appended to the ciphertext)
+ Added Custom padding mode (enter any single byte to use as padding)
+ Added option to compute hash of output during encrypt/decrypt
+ Added support for PEM private RSA PKCS#8 keys
+ Added ECDH-secp256k1, ECDH-ED25519, and Curve25119 key exchanges as derive functions (will ask for Other's Public Key)
+ Added ability for algorithms to change UI labels as appropriate (e.g. "Raw RSA" uses "Modulus" and "Exponent" instead of "Key" and "IV")
+ Added ability for algorithms to enable/disable supported key format radio buttons
+ Added ability for algorithms to accept no key (e.g. ROT13, CertUtilEncode)
+ Added AutoIT (MT) RNG algorithm
+ Added checkbox to toggle syncronized scrolling of hex views
+ Added support for "Drop N" to RC4 algorithm (parses as an integer string)
+ Added coloring of 0x00 bytes in hex views (dark gray)
+ Added Sosemanuk algorithm and unit test
+ Added CRC32 and MD4 hash algorithms
+ Added String Encoder tool - convert between ASCII/UTF8/UTF16 strings and bytes
+ Added export of public/private keys to clipboard in RSA Calculator
+ Added ASN.1 export to RSA Calculator
+ Added OAEP_SHA1, OAEP_SHA256, OAEP_384, and OAEP_512 padding modes (for RSA)
+ Added custom "Position" (Advanced -> Custom) to manually set the stream position used in Salsa20/ChaCha20
+ Added custom "Matrix" (Advanced -> Custom) to manually set the initial state used in Salsa20/ChaCha20 (parses the key, nonce, constant, and stream position)
+ Added support for CNG RSA key blobs in Blob Analyzer, RSA Calculator, and for encrypt/decrypt
+ Added "Sum XOR" stream cipher - a running sum is created from each byte of the key and XOR'd with the plaintext (i.e. seen in MountLocker ransomware)
+ Added "RC4 Custom Sbox" algorithm (parses as an integer string)
+ Added checkbox for appending Input text or base64
+ Added ability to reverse input bytes (Advanced -> Reverse Input Bytes)
+ Minor updates to library dependencies
+ Fixed AES CFB mode decryption for inputs not % blocksize (overcomes bug in .NET provider)
+ Fixed ECB mode to ignore IV if provided
+ Fixed HiddenTear preset
+ Fixed Generate Keystream operation using offset > 0
+ Added support for offset < 0 to Generate Keystream operation (syncs end of file relatively based on smaller file)
+ RSA Calculator now calculates N from P and Q if not provided
+ Fixed support for ASN.1 private RSA PKCS#1 keys that have an outer sequence
+ Fixed support for ASN.1 public RSA PKCS#1 keys that have an inner sequence
+ Fixed import/use of PEMs with missing positive byte marker on parameters
+ Fixed crash on short key found in Bruteforce Keys tool
+ Fixed Base Encoder to accept larger inputs
+ Fixed RSA key verification to allow other solutions for D (was causing verification to fail on legitimate keys)
+ Fixed hex views scrolling two lines instead of one per scroll click
+ Fixed hex views synced scrolling with scrollbar and keys
+ Fixed File Option -> Offset to assume relative to end of input if parsed value is negative
+ Fixed duplicate output from Key Finder when it was opened and closed multiple times
+ Fixed duplicate runs of Bruteforce Keys when it was opened and closed multiple times
+ Fixed XTS block mode to actually use IV (as Key2)
- Removed ECB analysis in Compare (wasn't working correctly)
|_ Replaced with Hash Analysis (checks for digest of Original in Encrypted)

## [1.4.0.3]
+ Fixed blob parsing (regression from 1.4.0.2 with internal endianness changes)

## [1.4.0.2]
+ Fixed Desert.jpg resource
+ Hex views:
	+ Added Esc (cancel selection) shortcut
	+ Added Home (go to beginning of current row) shortcut
	+ Added End (go to end of current row) shortcut
	+ Added auto ASCII/UTF-16 conversion when selecting
	+ Changed shortcuts to go to very beginning (Ctrl+Home) and very end of file (Ctrl+End)
	+ Fixed moving selection when start of selection is last byte
	+ Fixed page up when exactly one page down from byte 0
	+ Fixed clearing selection when pressing shift+up and start of selection is byte 0
	+ Fixed clearing selection when pressing shift+down and start of selection is last byte
	+ Fixed shift+up deselecting two rows
	+ Fixed release selection when pressing Home on byte 0 and End on last byte
+ Added support for finding cryptoblobs as ASCII strings in Key Finder
+ Added Esc (close) shortcut for all dialogs
+ Added "Flip Endian" tool to Blob Analyzer and RSA Calculator
+ Added drag-n-drop file support to IV textbox
+ Added "Custom Constant" (Advanced) to manually set the constant bytes used in Salsa20 (overrides default sigma/tau)
+ Added explicit OAEP padding to dropdown for RSA to be more clear (previously used OAEP if anything but None)
+ Added AES XTS block mode
+ Added HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512 derive functions
+ Added RSA (Raw) algorithm - provide d or e as Key, n as IV
+ Grouped algorithms by cipher type to make long dropdown easier to find an algorithm, now also shows full proper names for algorithms
+ Fixed detection of PEM keys without newlines in Key Finder
+ Fixed RC2, RC5, and RC6 algorithms to actually act like block ciphers - accept block mode, padding mode, and IV
+ Fixed RC4 keysize for CryptDeriveKey
+ Fixed RSA Calculator to parse hex like other inputs (ignore spaces, colons, commas, etc.)
+ Fixed progress bar of Bruteforce Keys tool
+ Redesigned Bruteforce Keys tool to accept a byte count (e.g. key file with raw byte keys appended)

## [1.4.0.1]
+ Added embedded Chrysanthemum.jpg and Desert.jpg (Windows 7 sample pictures) as input options
+ Added copy/paste for hex boxes in Compare tab
+ Added Ctrl+F (find) shortcut for all hex views
+ Added Ctrl+G (goto) shortcut for all hex views
+ Added Ctrl+O (Open File) and Ctrl+S (Save Output) shortcuts
+ Added selection length display to hex views
+ Added auto WORD/DWORD/QWORD conversion when selecting in hex views
+ Added some menu icons!
+ Enabled Compress button on Compress tab (note some algorithms are buggy, work in progress)
+ Enabled input menu for Compare tab (fills as Original)
+ Fixes with Swap button in Compare tab
+ Fixed block mode, padding mode, and IV for Serpent algorithm
+ Removed Input -> Raw Bytes (superceded by Paste option)

## [1.4.0.0]
+ Added entropy calculation for string outputs in RNG Tester
+ Seed, length, and modulus in RNG Tester now accepts expressions (e.g. x10)
+ Added modulus for string outputs in RNG Tester (as algorithm permits)
+ Added decoded views for Compare and Compress/Decompress tab - click on offset bar
+ Added new padding modes - Spaces (' ') and Ascii Zeros ('0') (used in Python crypto alot for some reason)
+ Added CertUtilEncode algorithm (certutil.exe -encode/-decode)
+ Fixed SymmetricAlgorithm's bug of not removing zero (0x00) padding
+ Fixed crash when clicking decode view with empty hex
+ Fixed crash when trying to open a file already open by another program
+ Fixed key length not populated in Blob Generator on load
+ Fixed accepting manual input of key length in Blob Generator
+ Added ASN.1 key usage for encrypt/decrypt
+ Added Addition/Subtraction encryption algorithms
+ Added Addition/Subtraction detection to Compare files tab
+ Added button to move output to input in Encrypt tab
+ Added button to swap original/encrypted in Compare files tab
+ Added search bytes buttons to all hex views
+ Added coloring of Newline sequence characters (purple) in hex editors
+ Minor version updates to library dependencies
+ Code rearranging/cleanup

## [1.3.0.9]
+ Fixed error with converting DWORDs
+ Fixed memory access errors when copy/paste contents to other hex editor programs (HxD in particular)
+ Added ASN.1 import and export to Blob Analyzer
+ Added basic XOR encryption detection to Compare files tab
+ Added Ctrl+A (select all) shortcut for all hex edit views
+ Added Base58 and Base58Check encodings to Base Encoder
+ Added Misty1 and Kasumi encryption algorithms (with unit tests)
+ Added Fermet encryption scheme (with unit test)
+ Added "Enter Text" for input
+ Added iterations for Hash

## [1.3.0.8]
+ File offset/length now accept expressions, including variables for the file length; e.g. "length - x10"
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
+ Added "Sequential Bytes" input - automatically generates 0x00 - 0xFF up to given limit
+ Input "Zeroes" and "Sequential Bytes" can also accept above expressions
+ Fixed accepting newlines in Base Encoder
+ Added input/output length display to Base Encoder
+ Added detection of ROT13-encoded keys to Key Finder
+ Added detection of damaged (but repairable) BLOBs to Key Finder
+ Added Blob Generator tool to Blob Analyzer - generate a random cryptoblob with specified parameters
+ Added "Bruteforce Keys" tool - attempts decryption using a key list and the specified encryption parameters of the main window
+ Added "Splice Remaining Bytes" checkbox to splice bytes before/after selected offset to the output
+ Fixed "PHP mt_rand" and "PHP 7.1 mt_rand" RNG algorithms (RNG Tester)
+ Added base64 detection for dragging key file into "Key" textbox
+ Added drag-and-drop file into Blob Analyzer (auto-detects input type)
+ Added export to clipboard for base64, PEM, and XML (BlobAnalyzer) - resorted menu options

## [1.3.0.7]
+ Added decoded view for original/encrypted bytes - click on offset bar
+ Added OpenSSL-compatible Derives (EVP_BytesToKey) - MD5 (pre OpenSSL 1.1.0c), and SHA256 (post OpenSSL 1.1.0c)
+ Added Preset feature - presets common crypto schemes
+ Presets for HiddenTear and OpenSSL
+ Fixed a fallback for incorrectly declared PKCS#8 PEM keys
+ Fixed detection of SIMPLEBLOBs in Key Finder
+ Fixed acceptance of keys with new lines (e.g. PEM) for the main window
+ Tweaked input fields expecting hex byte to ignore tabs, carriage returns, "h" prefixes, and bracket/braces

## [1.3.0.6]
+ RSA Calculator can now calculate primes (p and q) if given public and private exponents and modulus (n, e, and d)
+ Blob Analyzer repair option can fix private RSA key blobs with corrupted primes if above (n, e, d) variables are valid
+ Added basic support for CNG blobs in Blob Analyzer and Key Finder
+ Added generation of example RSA keys (cannot guarantee cryptographically safe!)
+ Fixed XSalsa20 algorithm

## [1.3.0.5]
+ Added repair option for private RSA key blobs (Blob Analyzer)
+ Added test vectors for Blowfish algorithm
+ Added C++ MT19937 (MT) RNG algorithm
+ Fixed bug with DeriveKey hashes when used with AES-256 (keysize is respected vs blocksize)
+ Updated dependant libraries

## [1.3.0.4]
+ Added extraction of some common PEM stubs (without BEGIN/END markers) to Key Finder
+ Fixed capture of PEM strings that are chunked in Key Finder
+ Fixed parsing of UTF16 strings in Key Finder
+ Fixed max length of characters allowed on input forms
+ Tweaked input fields expecting hex bytes to ignore "-"
+ Fixed pasting of hex strings in main window
+ Fixed bug with DeriveKey hashes using SHA-2 family of hashes
+ Fixed bug with DeriveKey hashes when used with AES-128
+ Added Generate Keystream (XORs two files from Compare tab, Operations -> Generate Keystream)
+ Added Bruteforce Algorithm (tries all algorithm, hash, block mode, padding mode combination with given key, Operations -> Bruteforcer Algorithm)

## [1.3.0.3]
+ Added ChaCha20 (IETF) algorithm
+ Added Little Endian option (currently only flips byte order for TEA/XTEA, Advanced -> Little Endian)
+ Organized IV related options (Advanced -> IV)
+ Added option to add an IV from UTF8 text (Advanced -> IV -> Enter Text IV)
+ Added RSA Broadcast Attack tool (Cracking -> RSA -> RSA Broadcast Attack, only supports e=3 currently)
+ Added XOR Attack tool (Cracking -> XOR -> XOR Attack)
+ Fixed bug with syncing hex editor with byte stream used for encrypting when saving
+ Tweaked any input field that expects hex bytes to ignore "0x" prefixes and commas (make pasting from code easier)

## [1.3.0.2]
+ Added PasswordDeriveBytes for key generation
+ Added option to enable/disable RFC2898/Password Derive functions from auto deriving the IV (Advanced -> Auto Derive IV)
+ Added PKCS#1 PEM parsing ("BEGIN RSA PUBLIC KEY")
+ Added UTF-16/wide string detection to Key Finder
+ Added progress updates to Key Finder
+ Added string input for XML to Blob Analyzer
+ Added new input for strings that accepts newlines (e.g. PEM or Base64 input of Blob Analyzer)
+ Fixed auto-generation of Salsa20 IV
+ Fixed enabling of Encrypt/Decrypt buttons when pasting or typing in input hexbox
+ Fixed long error messages that would break the status label of windows

## [1.3.0.1]
+ Added coloring of ASCII characters (orange) in hex editors
+ Added "Search Bytes" option (Operations)
+ Added modulus for RNG Tester
+ Fixed possible crash with comparing small files
+ Fixed filesize difference on drag-and-drop comparing
+ Fixed paste from context menu for hex editor
+ Fixed file info stats for manually edited hex
+ Tweaked tool menu options

## [1.3.0.0]
+ Updated target framework to .NET 4.6.1
+ Updated several internal libraries
+ Fixed copy function in hex editors
+ Added paste function to input (left hex editor in Encrypt/Decrypt tab)
+ Added display of generated key (click on the length)
+ Moved "Get IV From Input" to Advanced toolstrip (removed button)
+ Added finding PGP public and private keys in Key Finder
+ Fixed possible crash on Key Finder
+ Fixed a few false positives in Key Finder
+ Removed restriction of PE files for Key Finder (allow searching of binary dumps, etc)
+ GUI fixes for Display Bytes
+ Added "SharpAESCrypt" algorithm

## [1.2.0.6]
+ Added Base Encoder utility (Tools -> Base Encoder)
+ Added unit testing for RNG algorithms (automatically run on use in RNG Tester)
+ Added full validation of BLOBs
+ Added option to export RSA key as public or private key (RSA Calculator)
+ Added BSD libc rand (LCG) RNG algorithm
+ Added Java.util.Random (LCG) RNG algorithm
+ Added display of rounds used when encrypting/decrypting (on supported algorithms)
+ Fixed RSA decryption of data if it was originally encrypted by a CSP provider
+ Fixed random string generation with PowerShell and PowerShell5 RNG algorithms (to mimic -InputObject processing)
+ Fixed parsing of BLOBs if extra bytes are added in Blob Analyzer
+ Fixed export of BLOBs in Blob Analyzer to respect the proper output based on blob type
+ GUI fixes for RNG Tester

## [1.2.0.5]
+ Added base64 input for Encrypt/Decrypt tab
+ Fixed block mode and padding support for some algorithms
+ Fixed default IV size for some algorithms
+ Fixed Delphi (LCG) RNG algorithm
+ Added accessing RSA Calculator from main window
+ Fixed changing base for RSA Calculator variables
+ Added test vectors for IDEA algorithm
+ Additional error handling

## [1.2.0.4]
+ Added RSA Calculator utility to Blob Analyzer (Tools -> RSA Calculator)
+ Compare blob analysis now looks for any kind of BLOB
+ Added configurable Rounds for applicable algorithms (Advanced -> Rounds)
+ Added RC5 (16-bit wordsize) algorithm
+ Corrected RC5 wordsize wording (blocksize != wordsize)
- Removed "Salsa20_8" and "Salsa20_12" algorithms in favor of using Rounds config

## [1.2.0.3]
+ Added Rijndael (192-bit blocksize) algorithm
+ Added Rijndael (256-bit blocksize) algorithm
+ Added RC5 (64-bit wordsize) algorithm
+ Added detection of any kind of BLOB to Key Finder
+ Added output of the bitlength for RSA keys found as PEM/XML/Base64 in Key Finder
+ Added button to automatically extract first (blocksize) of input as IV

## [1.2.0.2]
+ Bugfix for parsing of SIMPLEBLOBs
+ Tweaks to Key Finder display

## [1.2.0.1]
+ Added base64 decode to Blob Analyzer
+ Added Key Finder utility
+ Internal re-write of BLOB parsing

## [1.2.0.0]
- First public release
