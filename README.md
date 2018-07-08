# crypto
Multiplatform Console Crypto Tool

**Introduction:**

Crypto is a command line utility that allows you to encode, decode, encrypt, decrypt and digest with files of any size. It has more than 64 bases, 35 cipherers and 126 digestive algorithms.
	
**System requirements:** 

This application is an executable console for x86 processors, and has been developed in C Sharp under .Net 2.0. This means that it's necessary to have installed the framework libraries in your system. In this sense, the application can be executed on other platforms that aren't Windows by means of [Mono](http://www.mono-project.com/).

For the rest, just copy the executable file to any folder you want, and run it with the desired command line option, according to your needs.
	
**Recommendations:**

For files that are too large, it's recommended to increase the maximum buffer size.

# Index

* [Usage](#usage)
* [Options](#options)
* [Input notes](#input-notes)
* [Modes](#modes)
* [Hashes](#hashes)
* [Curves](#curves)
* [Examples](#examples)
* [Releases](https://github.com/jar0l/crypto/releases)

# Usage:

        crypto [options...] input-file-name

# Options:

        -m  --mode            Algorithm mode. You can use the help combined with this 
                              modifier to list the available modes.

        -e  --enc             Encrypt or encode operation indicator.
        -d  --dec             Decrypt or decode operation indicator.
        -2  --b32-hex         For B32 mode. Uses the extended hex alphabet.
        -8  --no-rfc4648      For B32 and B64 modes. Encoding without the RFC4648 
                              specification.

        -1  --base-code       Custom characters to be encoding in BaseN without RFC4648 
                              specification. The length must be equal to or greater than 
                              the specified base number.

        -6  --base-line-wrap  Number of characters to adjust the lines for BaseN mode. 
                              The value must be in increments of 8 characters with B2, 
                              6 characters with B3, 4 characters from B4 to B6 (or B64 
                              with RFC4648), 3 characters from B7 to B15, and 2 
                              characters from B16 to B64 (without RFC4648). The maximum 
                              value is 252 for B3, 255 from B7 to B15, and 256 for all 
                              others.

        -5  --rounds          For RC5, SALSA20, and CHACHA the number of rounds should 
                              be a integer value (20 by default).

        -4  --rc5-64b         For RC5 mode. It indicates that 64-bit word should be 
                              used.

        -3  --vmpc-ksa3       For VMPC mode. It indicates that the Key Scheduling 
                              Algorithm should be used.

        -x  --max-buffer-size Maximum buffer size in bytes for read and write. Modes: 
                              All symmetric ciphers and PGP. The default value is 1024.

        -k  --key             The key characters must have a key size length divided by 
                              8. It must be accompanied by the initial vector in the 
                              terms subject to that modifier. This option is prioritized
                              over hash, password, salt, and iterations. Modes: All 
                              symmetric ciphers. This modifier supports hexadecimal byte 
                              notation by the escape characters \x (two-digit) and \u 
                              for Unicode (four-digit).

        -i  --initial-vector  It needs to be 16 characters for AES, 3DES, DES, RC2, 						
                              3FISH, and MARS. SALSA20 requires exactly 8 characters. 
                              The RIJNDAEL long must be equal to the block size divided 
                              by 8. With VMPC the value should be between 1 and 768 
                              depending on the block size. This modifier supports 
                              hexadecimal byte notation by the escape characters \x 
                              (two-digit) and \u for Unicode (four-digit).

        -p  --password        Word, phrase or file. Modes: All symmetric ciphers and PGP 
                              private key or x509 certificates (*.pfx or *.pem). This 
                              modifier supports hexadecimal byte notation by the escape 
                              characters \x (two-digit) and \u for Unicode (four-digit)
                              with symmetric ciphers.

        -s  --salt            At least 8 characters. Modes: All symmetric ciphers.
        -h  --hash            Hash algorithm. Modes: DIGEST, CHECKSUM, all symmetric  
                              ciphers, ECIES, DLIES, and ELGAMAL or RSA with OAEP 
                              (Bouncy Castle). You can use the help combined with this 
                              modifier to list the available hashes or for more info.

        -t  --iterations      Number of iterations to do. Range from 1 to 2147483647 
                              (1000 by default). You have to bear in mind that a 
                              greater number of iterations implies a slower process. 
                              Modes: All symmetric ciphers.

        -c  --cipher-mode     CBC (Cipher Block Chianing) by default for all symmetric 
                              block ciphers. The cipher modes CFB (Cipher feedback), or 
                              OFB (Output feedback) are valid for all block ciphers 
                              except AES. Other cipher modes like ECB (Electronic Code 
                              Book), or CTS (Cipher Text Stealing) are only valid for 
                              RC2, 3DES, DES, MARS, AES, and RIJNDAEL with initial 
                              vector.

        -n  --padding         X923, ZEROS, ISO10126, or PKCS7 (by default). Modes: 
                              3FISH, AES, 3DES, DES, RC2, and RIJNDAEL. MARS only 
                              support PKCS7, and the others block ciphers also support 
                              ISO7816D4 or TBC but no ZEROS padding mode. RSA and 
                              ELGAMAL support PKCS1 (by default) and ISO9796D1 is 
                              supported only by RSA with Bouncy Castle.

        -r  --random-gen      Random password and salt generator. Modes: All symmetric 
                              ciphers.

        -l  --block-size      The RIJNDAEL legal values: 128, 160, 192, 224, and 256 
                              (by default). The HC legal values: 128 (by default) or 
                              256. For VMPC the value must be between 8 and 6144 bits 
                              in increments of 8 bits (256 by default).

        -z  --feedback-size   For RIJNDAEL only. The feedback size determines the 
                              amount of data that is fed back to successive encryption 
                              or decryption operations. The feed back size cannot be 
                              greater than the block size.

        -y  --key-size        Key size in bits. You can use the help combined with this 
                              modifier for more info.

        -g  --key-pair-gen    Key pair generator. Modes: ECIES, DLIES, ELGAMAL, 
                              NACCACHE, RSA, and PGP. The public and private key file 
                              names will be required.

        -b  --public-key      Public key file name. Modes: ECIES, DLIES, RSA, PGP, 
                              NACCACHE, ELGAMAL, and all symmetric ciphers.

        -v  --private-key     Private key file name. Modes: ECIES, DLIES, RSA, PGP, 
                              NACCACHE, ELGAMAL, and all symmetric ciphers.

        -9  --x509-file        X509 certificate file name. Modes: RSA, PGP, and all 
                              symmetric ciphers.

        -0  --x509-store      X509 common name or thumbprint in the certificate store. 
                              Modes: RSA, PGP, and all symmetric ciphers.

        -f  --format          For Asymmetric keys. The available formats are: [XML] 
                              for intrinsic RSA mode; [B64] for RSA, ELGAMAL, NACCACHE,
                              ECIES, and DLIES modes; [ARMORED] for PGP mode.

        -a  --oaep            For ELGAMAL and RSA. Microsoft CryptoAPI only supports 
                              OAEP since Windows XP for RSA.

        -q  --pgp-cipher      Symmetric cipher for PGP encryption: AES128, AES192, 
                              AES256 (by default), BLOWFISH, 2FISH, CAST5, DES, 3DES,
                              IDEA, CAMELLIA128, CAMELLIA192, CAMELLIA256, and SAFER.

        -u  --crossbreeding   For RSA, ELGAMAL, and PGP. It allows use either keys from 
                              RSA to PGP and PGP to RSA or ELGAMAL to PGP and PGP to
                              ELGAMAL.

        -j  --tell-apart      Sets customized password and salt for each file in batch 
                              process with symmetric ciphers.

        -o  --output          Output file name or path.
        -w  --overwrite       Overwrites the existing output file(s) without asking.
        -7  --io-options      Input and output options. You can use the help combined 
                              with this modifier for more info.

        --export              For RSA, PGP, and ELGAMAL. Exports certificates and keys. 
                              You can use the help combined with this modifier for more 
                              info.

        --encoding            Character encoding for password, salt, key, and initial 
                              vector with symmetric ciphers and B64 mode. The available 
                              encodings  are: ASCII (by default), UNICODE-LE, UNICODE-BE,  
                              UTF-7, UTF-8, and UTF-32.

        --gost-box            Specifies s-box for GOST mode. The available s-boxes are: 
                              DEFAULT, E-TEST, E-A, E-B, E-C, E-D, D-TEST, D-A, IV, or 
                              empty string for nothing at all.

        --without-iv-tweak    Without tweak or initial vector if possible for symmetric 
                              block ciphers (with Bouncy Castle)

        --rsa-bouncy-castle   It uses the Bouncy Castle for RSA, PGP, and all symmetric
                              ciphers with key exchange (Key pair generation, 
                              encription, and decryption).

        --public-exponent     Long prime number for RSA or PGP mode with RSA algorithm 
                              and use of Bouncy Castle (65537 by default). For key pair 
                              generation only.

        --certainty           Percentage of certainty when prime numbers are produced 
                              with Bouncy Castle. For RSA, PGP, ELGAMAL, NACCACHE, 
                              ECDH, and DLIES modes. For key pair generation only.

        --small-primes        Length of small primes for NACCACHE mode (30 by default).
        --signature           Signature for encryption and decription. A file must be 
                              specified and private key is required for RSA mode. You 
                              can specify Probabilistic Signature Schema (PSS) or 
                              ISO9796D2 (for RSA mode only) before the file. Modes: RSA, 
                              NACCACHE, and ELGAMAL.

        --pgp-id              Identity for PGP key pair generation.
        --pgp-sha1            Uses SHA1 with PGP for key pair generation.
        --pgp-algorithm       Public and private keys algorithm for PGP mode. The 
                              available algorithms are: RSA (by default), ECDH, and 
                              ELGAMAL.

        --pgp-master          Master key pair type for PGP. The available masters are:
                              DSA (by default for ELGAMAL), ECDSA (by default for
                              ECDH), and RSA.

        --pgp-signature       Signature for PGP encryption and decription. The key pair 
                              or certificates will be required.

        --pgp-compress        It specifies a compression algorithm for encryption. The 
                              available algorithms are: BZIP2, ZIP (by default), ZLIB, 
                              and NONE.

        --ies-cipher          Symmetric cipher for ECIES and DLIES modes: AES (by 
                              default), RIJNDAEL, SERPENT, TNEPRES, CAMELLIA, GOST, 
                              2FISH, 3FISH, DES, 3DES, RC2, RC5, RC6, SKIPJACK, 
                              BLOWFISH, CAST5, CAST6, TEA, XTEA, SEED, IDEA, NOEKEON, 
                              or empty string for nothing at all.

        --curve               Specifies a curve name for ECIES mode and PGP with ECDSA 
                              master key or ECDH algorithm.

        --curve-store         Specifies a store of curves for ECIES mode and PGP with 
                              ECDSA master key or ECDH algorithm. The stores curve are: 
                              CUSTOM, TELETRUST, NIST, ANSSI, X962, GOST, and SEC.

        --show-store-curves   Shows the available curves in the specified store.
        --raise-pwd-exception Raises exception for incorrect password or salt.
        --inhibit-errors      Continue even with errors if possible in batch process.
        --inhibit-esc-chars   Does not process hexadecimal byte notation by the escape 
                              characters \x or \u for Unicode.

        --inhibit-delimiter   Does not process semicolon as a path delimiter.
        --input-notes         Show informative notes of input data.
        --examples            Show command line examples for specified mode.
        --help                Show usage info. This modifier can be combined with others 
                              from behind or ahead for more info.

# Input notes:

	> The parameter "file:", at the beginning of the modifier --password, allows to 
	  obtain the complete text of a file as password.

    > The parameter "batch:", at the beginning of the input file, processes the input 
	  data paths as batch files. The paths must be separated by line feed or semicolon 
	  unless otherwise indicated.

	> The semicolon character is the path delimiter unless otherwise indicated.

	> The parameter "public:" or "private:", at the beginning of the modifier 
	  --x509-file or --x509-store specifies the certificate type, otherwise they will be 
	  used in order of occurrence.


# Modes:

List of available modes.

**Encoding:**

      	Bn (Base n, Where n must be a number from 2 to 64)

**Symmetric Block Ciphers:**

      	RIJNDAEL
      	AES (Advanced Encryption Standard)
      	3DES (Triple Data Encryption Standard)
      	DES (Data Encryption Standard)
      	RC2 (Rivest Cipher 2)
      	RC5 (Rivest Cipher 5)
      	RC6 (Rivest Cipher 6)
      	MARS
      	SERPENT
      	TNEPRES
      	2FISH (Twofish)
      	3FISH (Threefish)
      	BLOWFISH
      	CAST5
      	CAST6
      	IDEA (International Data Encryption Algorithm)
      	GOST (The Government Standard of the USSR 28147)
      	NOEKEON
      	SEED
      	TEA
      	XTEA
      	SKIPJACK

**Symmetric Stream Ciphers:**

      	RC4 (Rivest Cipher 4)
      	ISAAC
      	SALSA20
      	XSALSA20
      	CHACHA
      	VMPC (Variably Modified Permutation Composition)
      	HC (Hongjun Cipher)

**Asymmetric Ciphers:**

      	RSA (Rivest, Shamir and Adleman)
      	PGP (Pretty Good Privacy, Open, RFC 4880)
      	ELGAMAL
      	NACCACHE

**Hybrids Ciphers:**

      	ECIES (Elliptic Curve Integrated Encryption Scheme)
      	DLIES (Discrete Logarithm Integrated Encryption Scheme)

**Others:**

      	DIGEST (Digest file mode)
      	CHECKSUM (Checksum file mode)

# Hashes:

List of available hashes.

**SHA-3** (Candidates):

      	BLAKE224
      	BLAKE256
      	BLAKE384
      	BLAKE512
      	BMW224 (Blue Midnight Wish)
      	BMW256 (Blue Midnight Wish)
      	BMW384 (Blue Midnight Wish)
      	BMW512 (Blue Midnight Wish)
      	CUBE224
      	CUBE256
      	CUBE384
      	CUBE512
      	ECHO224
      	ECHO256
      	ECHO384
      	ECHO512
      	FUGUE224
      	FUGUE256
      	FUGUE384
      	FUGUE512
      	GROESTL224
      	GROESTL256
      	GROESTL384
      	GROESTL512
      	HAMSI224
      	HAMSI256
      	HAMSI384
      	HAMSI512
      	JH224
      	JH256
      	JH384
      	JH512
      	KECCAK224 *
      	KECCAK256 *
      	KECCAK384 *
      	KECCAK512 *
      	LUFFA224
      	LUFFA256
      	LUFFA384
      	LUFFA512
      	SHABAL224
      	SHABAL256
      	SHABAL384
      	SHABAL512
      	SHAVITE224
      	SHAVITE256
      	SHAVITE384
      	SHAVITE512
      	SIMD224
      	SIMD256
      	SIMD384
      	SIMD512
      	SKEIN224
      	SKEIN256 *
      	SKEIN384
      	SKEIN512 *

**SHA-2:**

      	SHA224 *#@~
      	SHA256 *#@~
      	SHA384 *#@~
      	SHA512 *#@~ (By default)

**SHA** (Old):

      	SHA1 *#@~
      	SHA0

**MD** (Message Digest):

      	MD2 *#@
      	MD4 *@
      	MD5 *#@~

**Race Integrity Primitives Evaluation Message Digest:**

      	RIPEMD
      	RIPEMD128 *@
      	RIPEMD160 *#@
      	RIPEMD256 *@
      	RIPEMD320 *

**Others** (32-bit):

      	AP
      	BERNSTEIN
      	BERNSTEIN1
      	BKDR
      	DEK
      	DJB
      	DOTNET
      	ELF
      	FNV
      	FNV1A
      	JENKINS3
      	JS
      	MURMUR2
      	MURMUR3
      	ONEATTIME
      	PJW
      	ROTATING
      	RS
      	SDBM
      	SNX (Shift And Xor)
      	SUPERFAST

**Others** (64-bit):

      	FNV64
      	FNV1A64
		MURMUR2-64
		SIPHASH

**Others** (128-bit):

      	MURMUR3-128

**Others:**

      	GOST
      	GRINDAHL256
      	GRINDAHL512
      	HAS160
      	HAVAL3-128
      	HAVAL3-160
      	HAVAL3-192
      	HAVAL3-224
      	HAVAL3-256
      	HAVAL4-128
      	HAVAL4-160
      	HAVAL4-192
      	HAVAL4-224
      	HAVAL4-256
      	HAVAL5-128
      	HAVAL5-160
      	HAVAL5-192
      	HAVAL5-224
      	HAVAL5-256
      	PANAMA
      	RG32 (Radio Gatun)
      	RG64 (Radio Gatun)
      	SNEFRU4-128
      	SNEFRU4-256
      	SNEFRU8-128
      	SNEFRU8-256
      	TIGER2
      	TIGER3-192
      	TIGER4-192
      	WHIRLPOOL *

**Checksum:**

      	ADLER32
      	CRC32-IEEE
      	CRC32-CASTAGNOLI
      	CRC32-KOOPMAN
      	CRC32-Q
      	CRC64-ISO
      	CRC64-ECMA

\* DLIES and ECIES modes.

\# Signature for PGP mode.

@ Signature for RSA, ELGAMAL, and NACCACHE modes.

~ OAEP with Bouncy Castle.


# Curves:

List of available curves.

**Custom:**

      	curve25519  secp128r1   secp160k1   secp160r1   secp160r2   secp192k1

       	secp192r1   secp224k1   secp224r1   secp256k1   secp256r1   secp384r1

       	secp521r1   sect113r1   sect113r2   sect131r1   sect131r2   sect163k1

       	sect163r1   sect163r2   sect193r1   sect193r2   sect233k1   sect233r1

       	sect239k1   sect283k1   sect283r1   sect409k1   sect409r1   sect571k1

       	sect571r1


**Teletrust:**

       	brainpoolP160t1    brainpoolP384t1    brainpoolP384r1    brainpoolP192t1

       	brainpoolP224t1    brainpoolP160r1    brainpoolP256t1    brainpoolP192r1

       	brainpoolP224r1    brainpoolP512t1    brainpoolP256r1    brainpoolP512r1

       	brainpoolP320r1    brainpoolP320t1


**Nist:**

		K-571 K-283 B-283 B-233 P-256 B-409 B-571 P-521 P-384 B-163 K-163 K-233

		P-192 K-409 P-224


**Anssi:**

		FRP256v1


**X962:**

		c2tnb191v1   prime239v2   c2pnb272w1   c2pnb208w1   c2pnb304w1

		c2tnb239v1   c2tnb359v1   c2pnb176w1   prime239v1   c2pnb368w1

		c2pnb163v2   prime192v2   c2tnb239v2   c2pnb163v3   prime192v3

		c2tnb239v3   c2pnb163v1   prime192v1   c2tnb431r1   c2tnb191v2

		prime239v3   c2tnb191v3   prime256v1


**Gost:**

		GostR3410-2001-CryptoPro-B     GostR3410-2001-CryptoPro-A

		GostR3410-2001-CryptoPro-XchA  GostR3410-2001-CryptoPro-C

		GostR3410-2001-CryptoPro-XchB

**Sec:**

		secp224k1  sect193r1  sect571r1  secp521r1  secp256k1

  		secp112r2  secp224r1  sect193r2  sect409r1  sect131r1

  		secp160r2  sect131r2  secp192k1  sect233k1  sect163r1

  		secp128r1  secp160r1  sect233r1  sect113r2  secp128r2

  		secp384r1  secp112r1  sect163r2  secp192r1  sect163k1

  		sect239k1  secp160k1  sect283k1  sect409k1  sect571k1

  		sect113r1  sect283r1  secp256r1

# Examples:

**BASE-2**

		Encode:

			crypto -o file.b2 -m b2 -e file.txt
			crypto -o file.b2 -m b2 -6 128 -e file.txt
			crypto -o file.b2 -m b2 -1 01 -e file.txt

		Decode:

			crypto -o file.txt -m b2 -d file.b2
			crypto -o file.txt -m b2 -1 01 -d file.b2

**BASE-16**

		Encode:

			crypto -o file.b16 -m b16 -e file.txt
			crypto -o file.b16 -m b16 -6 128 -e file.txt
			crypto -o file.b16 -m b16 -1 0123456789abcdef -e file.txt

 		Decode:

			crypto -o file.txt -m b16 -d file.b16
			crypto -o file.txt -m b16 -1 0123456789abcdef -d file.b16

**BASE-32**

		Encode:

			crypto -o file.b32 -m b32 -e file.txt
			crypto -o file.b32 -m b32 -6 128 -e file.txt
			crypto -o file.b32 -m b32 -8 -e file.txt
			crypto -o file.b32 -m b32 -1 0123456789abcdefghijklmnopqrstuv
			       -e file.txt

		Decode:

			crypto -o file.txt -m b32 -d file.b32
			crypto -o file.txt -m b32 -8 -d file.b32
			crypto -o file.txt -m b32 -1 0123456789abcdefghijklmnopqrstuv
			       -d file.b32

**BASE-64**

		Encode:

			crypto -o file.b64 -m b64 -e file.txt
			crypto -o file.b64 -m b64 -6 128 -e file.txt
			crypto -o file.b64 -m b64 -8 -e file.txt
			crypto -o file.b64 -m b64 -1
			       0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU
			       VWXYZ+/ -e file.txt

 		Decode:

			crypto -o file.txt -m b64 -d file.b64
			crypto -o file.txt -m b64 -8 -d file.b64
			crypto -o file.txt -m b64 -1
			       0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU
			       VWXYZ+/ -d file.b64

**DIGEST**

			crypto -m digest file.bin
			crypto -m digest -h sha256 file.bin
			crypto -o file.txt -m digest -h md5 file.bin

**CHECKSUM**

			crypto -m checksum -h adler32 file.bin
			crypto -o file.txt -m checksum -h crc32-ieee file.bin

**AES**

		Encryption:

			crypto -o file.aes -m aes -e file.bin
			crypto -o file.aes -m aes -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.aes -m aes -p file:"my password file.txt" -e
			       file.bin

			crypto -o file.aes -m aes -s "" -h sha1 -e file.bin
			crypto -o file.aes -m aes -b rsa-public.key -e file.bin
			crypto -o file.aes -m aes -b elgamal-public.key -e file.bin
			crypto -o file.aes -m aes -b naccache-public.key -e file.bin
			crypto -o file.aes -m aes -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.aes -m aes -9 public.cer -e file.bin
			crypto -o file.aes -m aes -9 public.pem -e file.bin
			crypto -o file.aes -m aes -y 128 -k 1234567890123456 -i
			       6543210987654321 -e file.bin

		Decryption:

			crypto -o file.bin -m aes -d file.aes
			crypto -o file.bin -m aes -p "my password" -s "my salt8" -d
			       file.aes

			crypto -o file.bin -m aes -p file:"my password file.txt" -d
			       file.aes

			crypto -o file.bin -m aes -s "" -h sha1 -d file.aes
			crypto -o file.bin -m aes -v rsa-private.key -d file.aes
			crypto -o file.bin -m aes -v elgamal-private.key -d file.aes
			crypto -o file.bin -m aes -v naccache-private.key -d file.aes
			crypto -o file.bin -m aes -b ecdh-public.key -v
			       ecdh-private.key -d file.aes

			crypto -o file.bin -m aes -9 private.pfx -d file.aes
			crypto -o file.bin -m aes -9 private.pem -d file.aes
			crypto -o file.bin -m aes -y 128 -k 1234567890123456 -i
			       6543210987654321 -d file.aes

**RIJNDAEL**

		Encryption:

			crypto -o file.rij -m rijndael -e file.bin
			crypto -o file.rij -m rijndael -s "" -h sha1 -e file.bin
			crypto -o file.rij -m rijndael -b rsa-public.key -e file.bin
			crypto -o file.rij -m rijndael -b elgamal-public.key -e file.bin
			crypto -o file.rij -m rijndael -b naccache-public.key -e
			       file.bin

			crypto -o file.rij -m rijndael -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.rij -m rijndael -9 public.cer -e file.bin
			crypto -o file.rij -m rijndael -9 public.pem -e file.bin
			crypto -o file.rij -m rijndael -y 128 -l 128 -k
			       1234567890123456 -i 6543210987654321 -e file.bin

		Decryption:

			crypto -o file.bin -m rijndael -d file.rij
			crypto -o file.bin -m rijndael -s "" -h sha1 -d file.rij
			crypto -o file.bin -m rijndael -v rsa-private.key -d file.rij
			crypto -o file.bin -m rijndael -v elgamal-private.key -d
			       file.rij

			crypto -o file.bin -m rijndael -v naccache-private.key -d
			       file.rij

			crypto -o file.bin -m rijndael -b ecdh-public.key -v
			       ecdh-private.key -d file.rij

			crypto -o file.bin -m rijndael -9 private.cer -d file.rij
			crypto -o file.bin -m rijndael -9 private.pem -d file.rij
			crypto -o file.bin -m rijndael -y 128 -l 128 -k
			       1234567890123456 -i 6543210987654321 -d file.rij
					 
**TRIPLE-DES**

		Encryption:

			crypto -o file.3des -m 3des -e file.bin
			crypto -o file.3des -m 3des -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.3des -m 3des -p file:"my password file.txt" -e
			       file.bin

			crypto -o file.3des -m 3des -s "" -h sha1 -e file.bin
			crypto -o file.3des -m 3des -b rsa-public.key -e file.bin
			crypto -o file.3des -m 3des -b elgamal-public.key -e file.bin
			crypto -o file.3des -m 3des -b naccache-public.key -e file.bin
			crypto -o file.3des -m 3des -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.3des -m 3des -9 public.cer -e file.bin
			crypto -o file.3des -m 3des -9 public.pem -e file.bin
			crypto -o file.3des -m 3des -y 128 -k 1234567890123456 -i
			       6543210987654321 -e file.bin

 		Decryption:

			crypto -o file.bin -m 3des -d file.3des
			crypto -o file.bin -m 3des -p "my password" -s "my salt8" -d
			       file.3des

			crypto -o file.bin -m 3des -p file:"my password file.txt" -d
			       file.3des

			crypto -o file.bin -m 3des -s "" -h sha1 -d file.3des
			crypto -o file.bin -m 3des -v rsa-private.key -d file.3des
			crypto -o file.bin -m 3des -v elgamal-private.key -d file.3des
			crypto -o file.bin -m 3des -v naccache-private.key -d file.3des
			crypto -o file.bin -m 3des -b ecdh-public.key -v
			       ecdh-private.key -d file.3des

			crypto -o file.bin -m 3des -9 private.pfx -d file.3des
			crypto -o file.bin -m 3des -9 private.pem -d file.3des
			crypto -o file.bin -m 3des -y 128 -k 1234567890123456 -i
			       6543210987654321 -d file.3des

**DES**

		Encryption:

			crypto -o file.des -m des -e file.bin
			crypto -o file.des -m des -p "my password" -s "my salt8" -e file.bin
			crypto -o file.des -m des -p file:"my password file.txt" -e file.bin

			crypto -o file.des -m des -s "" -h sha1 -e file.bin
			crypto -o file.des -m des -b rsa-public.key -e file.bin
			crypto -o file.des -m des -b elgamal-public.key -e file.bin
			crypto -o file.des -m des -b naccache-public.key -e file.bin
			crypto -o file.des -m des -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.des -m des -9 public.cer -e file.bin
			crypto -o file.des -m des -9 public.pem -e file.bin
			crypto -o file.des -m des -k 12345678 -i 87654321 -e file.bin


		Decryption:

			crypto -o file.bin -m des -d file.des
			crypto -o file.bin -m des -p "my password" -s "my salt8" -d file.des
			crypto -o file.bin -m des -p file:"my password file.txt" -d file.des
			crypto -o file.bin -m des -s "" -h sha1 -d file.des
			crypto -o file.bin -m des -v rsa-private.key -d file.des
			crypto -o file.bin -m des -v elgamal-private.key -d file.des
			crypto -o file.bin -m des -v naccache-private.key -d file.des
			crypto -o file.bin -m des -b ecdh-public.key -v
			       ecdh-private.key -d file.des

			crypto -o file.bin -m des -9 private.pfx -d file.des
			crypto -o file.bin -m des -9 private.pem -d file.des
			crypto -o file.bin -m des -k 12345678 -i 87654321 -d file.des

**MARS**

		Encryption:

			crypto -o file.mar -m mars -e file.bin
			crypto -o file.mar -m mars -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.mar -m mars -p file:"my password file.txt" -e
			       file.bin

			crypto -o file.mar -m mars -s "" -h sha1 -e file.bin
			crypto -o file.mar -m mars -b rsa-public.key -e file.bin
			crypto -o file.mar -m mars -b elgamal-public.key -e file.bin
			crypto -o file.mar -m mars -b naccache-public.key -e file.bin
			crypto -o file.mar -m mars -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.mar -m mars -9 public.cer -e file.bin
			crypto -o file.mar -m mars -9 public.pem -e file.bin
			crypto -o file.mar -m mars -y 128 -k 1234567890123456 -i
			       6543210987654321 -e file.bin

		Decryption:

			crypto -o file.bin -m mars -d file.mar
			crypto -o file.bin -m mars -p "my password" -s "my salt8" -d
			       file.mar

			crypto -o file.bin -m mars -p file:"my password file.txt" -d
			       file.mar

			crypto -o file.bin -m mars -s "" -h sha1 -d file.mar
			crypto -o file.bin -m mars -v rsa-private.key -d file.mar
			crypto -o file.bin -m mars -v elgamal-private.key -d file.mar
			crypto -o file.bin -m mars -v naccache-private.key -d file.mar
			crypto -o file.bin -m mars -b ecdh-public.key -v
			       ecdh-private.key -d file.mar

			crypto -o file.bin -m mars -9 private.pfx -d file.mar
			crypto -o file.bin -m mars -9 private.pem -d file.mar
			crypto -o file.bin -m mars -y 128 -k 1234567890123456 -i
			       6543210987654321 -d file.mar

**SALSA20**

		Encryption:

			crypto -o file.sal -m salsa20 -e file.bin
			crypto -o file.sal -m salsa20 -s "" -h sha1 -e file.bin
			crypto -o file.sal -m salsa20 -b rsa-public.key -e file.bin
			crypto -o file.sal -m salsa20 -b elgamal-public.key -e file.bin
			crypto -o file.sal -m salsa20 -b naccache-public.key -e file.bin
			crypto -o file.sal -m salsa20 -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.sal -m salsa20 -9 public.cer -e file.bin
			crypto -o file.sal -m salsa20 -9 public.pem -e file.bin
			crypto -o file.sal -m salsa20 -y 128 -k 1234567890123456 -i
			       87654321 -e file.bin


		Decryption:

			crypto -o file.bin -m salsa20 -d file.sal
			crypto -o file.bin -m salsa20 -s "" -h sha1 -d file.sal
			crypto -o file.bin -m salsa20 -v rsa-private.key -d file.sal
			crypto -o file.bin -m salsa20 -v elgamal-private.key -d file.sal
			crypto -o file.bin -m salsa20 -v naccache-private.key -d
			       file.sal

			crypto -o file.bin -m salsa20 -b ecdh-public.key -v
			       ecdh-private.key -d file.sal

			crypto -o file.bin -m salsa20 -9 private.pfx -d file.sal
			crypto -o file.bin -m salsa20 -9 private.pem -d file.sal
			crypto -o file.bin -m salsa20 -y 128 -k 1234567890123456 -i
			       87654321 -d file.sal

**XSALSA20**

		Encryption:

			crypto -o file.x20 -m xsalsa20 -e file.bin
			crypto -o file.x20 -m xsalsa20 -s "" -h sha1 -e file.bin
			crypto -o file.x20 -m xsalsa20 -b rsa-public.key -e file.bin
			crypto -o file.x20 -m xsalsa20 -b elgamal-public.key -e file.bin
			crypto -o file.x20 -m xsalsa20 -b naccache-public.key -e
			       file.bin

			crypto -o file.x20 -m xsalsa20 -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.x20 -m xsalsa20 -9 public.cer -e file.bin
			crypto -o file.x20 -m xsalsa20 -9 public.pem -e file.bin

		Decryption:

			crypto -o file.bin -m xsalsa20 -d file.x20
			crypto -o file.bin -m xsalsa20 -s "" -h sha1 -d file.x20
			crypto -o file.bin -m xsalsa20 -v rsa-private.key -d file.x20
			crypto -o file.bin -m xsalsa20 -v elgamal-private.key -d
			       file.x20

			crypto -o file.bin -m xsalsa20 -v naccache-private.key -d
			       file.x20

			crypto -o file.bin -m xsalsa20 -b ecdh-public.key -v
			       ecdh-private.key -d file.x20

			crypto -o file.bin -m xsalsa20 -9 private.pfx -d file.x20
			crypto -o file.bin -m xsalsa20 -9 private.pem -d file.x20

**CHACHA**

		Encryption:

			crypto -o file.cha -m chacha -e file.bin
			crypto -o file.cha -m chacha -s "" -h sha1 -e file.bin
			crypto -o file.cha -m chacha -b rsa-public.key -e file.bin
			crypto -o file.cha -m chacha -b elgamal-public.key -e file.bin
			crypto -o file.cha -m chacha -b naccache-public.key -e file.bin
			crypto -o file.cha -m chacha -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.cha -m chacha -9 public.cer -e file.bin
			crypto -o file.cha -m chacha -9 public.pem -e file.bin
			crypto -o file.cha -m chacha -y 128 -k 1234567890123456 -i
			       87654321 -e file.bin

		Decryption:

			crypto -o file.bin -m chacha -d file.cha
			crypto -o file.bin -m chacha -s "" -h sha1 -d file.cha
			crypto -o file.bin -m chacha -v rsa-private.key -d file.cha
			crypto -o file.bin -m chacha -v elgamal-private.key -d file.cha
			crypto -o file.bin -m chacha -v naccache-private.key -d file.cha
			crypto -o file.bin -m chacha -b ecdh-public.key -v
			       ecdh-private.key -d file.cha

			crypto -o file.bin -m chacha -9 private.pfx -d file.cha
			crypto -o file.bin -m chacha -9 private.pem -d file.cha
			crypto -o file.bin -m chacha -y 128 -k 1234567890123456 -i
			       87654321 -d file.cha

**VMPC**

		Encryption:

			crypto -o file.vmp -m vmpc -e file.bin
			crypto -o file.vmp -m vmpc -3 -e file.bin
			crypto -o file.vmp -m vmpc -s "" -h sha1 -e file.bin
			crypto -o file.vmp -m vmpc -b rsa-public.key -e file.bin
			crypto -o file.vmp -m vmpc -b elgamal-public.key -e file.bin
			crypto -o file.vmp -m vmpc -b naccache-public.key -e file.bin
			crypto -o file.vmp -m vmpc -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.vmp -m vmpc -9 public.cer -e file.bin
			crypto -o file.vmp -m vmpc -9 public.pem -e file.bin
			crypto -o file.vmp -m vmpc -y 64 -l 64 -k 12345678 -i 87654321
			       -e file.bin


		Decryption:

			crypto -o file.bin -m vmpc -d file.vmp
			crypto -o file.bin -m vmpc -3 -d file.vmp
			crypto -o file.bin -m vmpc -s "" -h sha1 -d file.vmp
			crypto -o file.bin -m vmpc -v rsa-private.key -d file.vmp
			crypto -o file.bin -m vmpc -v elgamal-private.key -d file.vmp
			crypto -o file.bin -m vmpc -v naccache-private.key -d file.vmp
			crypto -o file.bin -m vmpc -b ecdh-public.key -v
			       ecdh-private.key -d file.vmp

			crypto -o file.bin -m vmpc -9 private.pfx -d file.vmp
			crypto -o file.bin -m vmpc -9 private.pem -d file.vmp
			crypto -o file.bin -m vmpc -y 64 -l 64 -k 12345678 -i 87654321
			       -d file.vmp

**RC2**

 		Encryption:

			crypto -o file.rc2 -m rc2 -e file.bin
			crypto -o file.rc2 -m rc2 -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.rc2 -m rc2 -p file:"my password file.txt" -e
			       file.bin

			crypto -o file.rc2 -m rc2 -s "" -h sha1 -e file.bin
			crypto -o file.rc2 -m rc2 -b rsa-public.key -e file.bin
			crypto -o file.rc2 -m rc2 -b elgamal-public.key -e file.bin
			crypto -o file.rc2 -m rc2 -b naccache-public.key -e file.bin
			crypto -o file.rc2 -m rc2 -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.rc2 -m rc2 -9 public.cer -e file.bin
			crypto -o file.rc2 -m rc2 -9 public.pem -e file.bin
			crypto -o file.rc2 -m rc2 -y 64 -k 12345678 -i 87654321 -e
			       file.bin

		Decryption:

      		crypto -o file.bin -m rc2 -d file.rc2
			crypto -o file.bin -m rc2 -p "my password" -s "my salt8" -d
			       file.rc2

			crypto -o file.bin -m rc2 -p file:"my password file.txt" -d
			       file.rc2

			crypto -o file.bin -m rc2 -s "" -h sha1 -d file.rc2
			crypto -o file.bin -m rc2 -v rsa-private.key -d file.rc2
			crypto -o file.bin -m rc2 -v elgamal-private.key -d file.rc2
			crypto -o file.bin -m rc2 -v naccache-private.key -d file.rc2
			crypto -o file.bin -m rc2 -b ecdh-public.key -v
			       ecdh-private.key -d file.rc2

			crypto -o file.bin -m rc2 -9 private.pfx -d file.rc2
			crypto -o file.bin -m rc2 -9 private.pem -d file.rc2
			crypto -o file.bin -m rc2 -y 64 -k 12345678 -i 87654321 -d
			       file.rc2

**CAMELLIA**

		Encryption:

			crypto -o file.cam -m camellia -e file.bin
			crypto -o file.cam -m camellia -y 128 -k 1234567890123456 -e
			       file.bin

			crypto -o file.cam -m camellia -s "" -h sha1 -e file.bin
			crypto -o file.cam -m camellia -b rsa-public.key -e file.bin
			crypto -o file.cam -m camellia -b elgamal-public.key -e file.bin
			crypto -o file.cam -m camellia -b naccache-public.key -e
			       file.bin

			crypto -o file.cam -m camellia -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.cam -m camellia -9 public.cer -e file.bin
			crypto -o file.cam -m camellia -9 public.pem -e file.bin
			crypto -o file.cam -m camellia -p "my password" -s "my salt8"
			       -e file.bin

			crypto -o file.cam -m camellia -p file:"my password file.txt"
			       -e file.bin

		Decryption:

			crypto -o file.bin -m camellia -d file.cam
			crypto -o file.bin -m camellia -y 128 -k 1234567890123456 -d
			       file.cam

			crypto -o file.bin -m camellia -s "" -h sha1 -d file.cam
			crypto -o file.bin -m camellia -v rsa-private.key -d file.cam
			crypto -o file.bin -m camellia -v elgamal-private.key -d
			       file.cam

			crypto -o file.bin -m camellia -v naccache-private.key -d
			       file.cam

			crypto -o file.bin -m camellia -b ecdh-public.key -v
			       ecdh-private.key -d file.cam

			crypto -o file.bin -m camellia -9 private.pfx -d file.cam
			crypto -o file.bin -m camellia -9 private.pem -d file.cam
			crypto -o file.bin -m camellia -p "my password" -s "my salt8"
			       -d file.cam

			crypto -o file.bin -m camellia -p file:"my password file.txt"
			       -d file.cam

**BLOWFISH**

		Encryption:

			crypto -o file.blf -m blowfish -e file.bin
			crypto -o file.blf -m blowfish -y 128 -k 1234567890123456 -e
			       file.bin

			crypto -o file.blf -m blowfish -s "" -h sha1 -e file.bin
			crypto -o file.blf -m blowfish -b rsa-public.key -e file.bin
			crypto -o file.blf -m blowfish -b elgamal-public.key -e file.bin
			crypto -o file.blf -m blowfish -b naccache-public.key -e
			       file.bin

			crypto -o file.blf -m blowfish -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.blf -m blowfish -9 public.cer -e file.bin
			crypto -o file.blf -m blowfish -9 public.pem -e file.bin
			crypto -o file.blf -m blowfish -p "my password" -s "my salt8"
			       -e file.bin

			crypto -o file.blf -m blowfish -p file:"my password file.txt"
			       -e file.bin


		Decryption:

			crypto -o file.bin -m blowfish -d file.blf
			crypto -o file.bin -m blowfish -y 128 -k 1234567890123456 -d
			       file.blf

			crypto -o file.bin -m blowfish -s "" -h sha1 -d file.blf
			crypto -o file.bin -m blowfish -v rsa-private.key -d file.blf
			crypto -o file.bin -m blowfish -v elgamal-private.key -d
			       file.blf

			crypto -o file.bin -m blowfish -v naccache-private.key -d
			       file.blf

			crypto -o file.bin -m blowfish -b ecdh-public.key -v
			       ecdh-private.key -d file.blf

			crypto -o file.bin -m blowfish -9 private.pfx -d file.blf
			crypto -o file.bin -m blowfish -9 private.pem -d file.blf
			crypto -o file.bin -m blowfish -p "my password" -s "my salt8"
			       -d file.blf

			crypto -o file.bin -m blowfish -p file:"my password file.txt"
			       -d file.blf

**2FISH**

		Encryption:

			crypto -o file.2f -m 2fish -e file.bin
			crypto -o file.2f -m 2fish -y 128 -k 1234567890123456 -e
			       file.bin

			crypto -o file.2f -m 2fish -s "" -h sha1 -e file.bin
			crypto -o file.2f -m 2fish -b rsa-public.key -e file.bin
			crypto -o file.2f -m 2fish -b elgamal-public.key -e file.bin
			crypto -o file.2f -m 2fish -b naccache-public.key -e file.bin
			crypto -o file.2f -m 2fish -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.2f -m 2fish -9 public.cer -e file.bin
			crypto -o file.2f -m 2fish -9 public.pem -e file.bin
			crypto -o file.2f -m 2fish -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.2f -m 2fish -p file:"my password file.txt" -e
			       file.bin

		Decryption:

			crypto -o file.bin -m 2fish -d file.2f
			crypto -o file.bin -m 2fish -y 128 -k 1234567890123456 -d
			       file.2f

			crypto -o file.bin -m 2fish -s "" -h sha1 -d file.2f
			crypto -o file.bin -m 2fish -v rsa-private.key -d file.2f
			crypto -o file.bin -m 2fish -v elgamal-private.key -d file.2f
			crypto -o file.bin -m 2fish -v naccache-private.key -d file.2f
			crypto -o file.bin -m 2fish -b ecdh-public.key -v
			       ecdh-private.key -d file.2f

			crypto -o file.bin -m 2fish -9 private.pfx -d file.2f
			crypto -o file.bin -m 2fish -9 private.pem -d file.2f
			crypto -o file.bin -m 2fish -p "my password" -s "my salt8" -d
			       file.2f

			crypto -o file.bin -m 2fish -p file:"my password file.txt" -d
			       file.2f

**3FISH**

		Encryption:

			crypto -o file.3f -m 3fish -e file.bin
			crypto -o file.3f -m 3fish -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.3f -m 3fish -p file:"my password file.txt" -e
			       file.bin

			crypto -o file.3f -m 3fish -s "" -h sha1 -e file.bin
			crypto -o file.3f -m 3fish -b rsa-public.key -e file.bin
			crypto -o file.3f -m 3fish -b elgamal-public.key -e file.bin
			crypto -o file.3f -m 3fish -b naccache-public.key -e file.bin
			crypto -o file.3f -m 3fish -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.3f -m 3fish -9 public.cer -e file.bin
			crypto -o file.3f -m 3fish -9 public.pem -e file.bin
			crypto -o file.3f -m 3fish -k 12345678901234567890123456789012
			       -i 6543210987654321 -e file.bin


		Decryption:

			crypto -o file.bin -m 3fish -d file.3f
			crypto -o file.bin -m 3fish -p "my password" -s "my salt8" -d
			       file.3f

			crypto -o file.bin -m 3fish -p file:"my password file.txt" -d
			       file.3f

			crypto -o file.bin -m 3fish -s "" -h sha1 -d file.3f
			crypto -o file.bin -m 3fish -v rsa-private.key -d file.3f
			crypto -o file.bin -m 3fish -v elgamal-private.key -d file.3f
			crypto -o file.bin -m 3fish -v naccache-private.key -d file.3f
			crypto -o file.bin -m 3fish -b ecdh-public.key -v
			       ecdh-private.key -d file.3f

			crypto -o file.bin -m 3fish -9 private.pfx -d file.3f
			crypto -o file.bin -m 3fish -9 private.pem -d file.3f
			crypto -o file.bin -m 3fish -k 12345678901234567890123456789012
			       -i 6543210987654321 -d file.3f

**SERPENT**

		Encryption:

			crypto -o file.ser -m serpent -e file.bin
			crypto -o file.ser -m serpent -y 128 -k 1234567890123456 -e
			       file.bin

			crypto -o file.ser -m serpent -s "" -h sha1 -e file.bin
			crypto -o file.ser -m serpent -b rsa-public.key -e file.bin
			crypto -o file.ser -m serpent -b elgamal-public.key -e file.bin
			crypto -o file.ser -m serpent -b naccache-public.key -e file.bin
			crypto -o file.ser -m serpent -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.ser -m serpent -9 public.cer -e file.bin
			crypto -o file.ser -m serpent -9 public.pem -e file.bin
			crypto -o file.ser -m serpent -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.ser -m serpent -p file:"my password file.txt" -e
			       file.bin

 		Decryption:

			crypto -o file.bin -m serpent -d file.ser
			crypto -o file.bin -m serpent -y 128 -k 1234567890123456 -d
			       file.ser

			crypto -o file.bin -m serpent -s "" -h sha1 -d file.ser
			crypto -o file.bin -m serpent -v rsa-private.key -d file.ser
			crypto -o file.bin -m serpent -v elgamal-private.key -d file.ser
			crypto -o file.bin -m serpent -v naccache-private.key -d
			       file.ser

			crypto -o file.bin -m serpent -b ecdh-public.key -v
			       ecdh-private.key -d file.ser

			crypto -o file.bin -m serpent -9 private.pfx -d file.ser
			crypto -o file.bin -m serpent -9 private.pem -d file.ser
			crypto -o file.bin -m serpent -p "my password" -s "my salt8" -d
			       file.ser

			crypto -o file.bin -m serpent -p file:"my password file.txt" -d
			       file.ser

**CAST5**

		Encryption:

			crypto -o file.c5 -m cast5 -e file.bin
			crypto -o file.c5 -m cast5 -y 128 -k 1234567890123456 -e
			       file.bin

			crypto -o file.c5 -m cast5 -s "" -h sha1 -e file.bin
			crypto -o file.c5 -m cast5 -b rsa-public.key -e file.bin
			crypto -o file.c5 -m cast5 -b elgamal-public.key -e file.bin
			crypto -o file.c5 -m cast5 -b naccache-public.key -e file.bin
			crypto -o file.c5 -m cast5 -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.c5 -m cast5 -9 public.cer -e file.bin
			crypto -o file.c5 -m cast5 -9 public.pem -e file.bin
			crypto -o file.c5 -m cast5 -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.c5 -m cast5 -p file:"my password file.txt" -e
			       file.bin


		Decryption:

			crypto -o file.bin -m cast5 -d file.c5
			crypto -o file.bin -m cast5 -y 128 -k 1234567890123456 -d
			       file.c5

			crypto -o file.bin -m cast5 -s "" -h sha1 -d file.c5
			crypto -o file.bin -m cast5 -v rsa-private.key -d file.c5
			crypto -o file.bin -m cast5 -v elgamal-private.key -d file.c5
			crypto -o file.bin -m cast5 -v naccache-private.key -d file.c5
			crypto -o file.bin -m cast5 -b ecdh-public.key -v
			       ecdh-private.key -d file.c5

			crypto -o file.bin -m cast5 -9 private.pfx -d file.c5
			crypto -o file.bin -m cast5 -9 private.pem -d file.c5
			crypto -o file.bin -m cast5 -p "my password" -s "my salt8" -d
			       file.c5

			crypto -o file.bin -m cast5 -p file:"my password file.txt" -d
			       file.c5

**CAST6**

		Encryption:

			crypto -o file.c6 -m cast6 -e file.bin
			crypto -o file.c6 -m cast6 -y 128 -k 1234567890123456 -e
			       file.bin

			crypto -o file.c6 -m cast6 -s "" -h sha1 -e file.bin
			crypto -o file.c6 -m cast6 -b rsa-public.key -e file.bin
			crypto -o file.c6 -m cast6 -b elgamal-public.key -e file.bin
			crypto -o file.c6 -m cast6 -b naccache-public.key -e file.bin
			crypto -o file.c6 -m cast6 -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.c6 -m cast6 -9 public.cer -e file.bin
			crypto -o file.c6 -m cast6 -9 public.pem -e file.bin
			crypto -o file.c6 -m cast6 -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.c6 -m cast6 -p file:"my password file.txt" -e
			       file.bin

		Decryption:

			crypto -o file.bin -m cast6 -d file.c6
			crypto -o file.bin -m cast6 -y 128 -k 1234567890123456 -d
			       file.c6

			crypto -o file.bin -m cast6 -s "" -h sha1 -d file.c6
			crypto -o file.bin -m cast6 -v rsa-private.key -d file.c6
			crypto -o file.bin -m cast6 -v elgamal-private.key -d file.c6
			crypto -o file.bin -m cast6 -v naccache-private.key -d file.c6
			crypto -o file.bin -m cast6 -b ecdh-public.key -v
			       ecdh-private.key -d file.c6

			crypto -o file.bin -m cast6 -9 private.pfx -d file.c6
			crypto -o file.bin -m cast6 -9 private.pem -d file.c6
			crypto -o file.bin -m cast6 -p "my password" -s "my salt8" -d
			       file.c6

			crypto -o file.bin -m cast6 -p file:"my password file.txt" -d
			       file.c6

**IDEA**

		Encryption:

			crypto -o file.ide -m idea -e file.bin
			crypto -o file.ide -m idea -k 1234567890123456 -e file.bin
			crypto -o file.ide -m idea -s "" -h sha1 -e file.bin
			crypto -o file.ide -m idea -b rsa-public.key -e file.bin
			crypto -o file.ide -m idea -b elgamal-public.key -e file.bin
			crypto -o file.ide -m idea -b naccache-public.key -e file.bin
			crypto -o file.ide -m idea -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.ide -m idea -9 public.cer -e file.bin
			crypto -o file.ide -m idea -9 public.pem -e file.bin
			crypto -o file.ide -m idea -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.ide -m idea -p file:"my password file.txt" -e
			       file.bin

		Decryption:

			crypto -o file.bin -m idea -d file.ide
			crypto -o file.bin -m idea -k 1234567890123456 -d file.ide
			crypto -o file.bin -m idea -s "" -h sha1 -d file.ide
			crypto -o file.bin -m idea -v rsa-private.key -d file.ide
			crypto -o file.bin -m idea -v elgamal-private.key -d file.ide
			crypto -o file.bin -m idea -v naccache-private.key -d file.ide
			crypto -o file.bin -m idea -b ecdh-public.key -v
			       ecdh-private.key -d file.ide

			crypto -o file.bin -m idea -9 private.pfx -d file.ide
			crypto -o file.bin -m idea -9 private.pem -d file.ide
			crypto -o file.bin -m idea -p "my password" -s "my salt8" -d
			       file.ide

			crypto -o file.bin -m idea -p file:"my password file.txt" -d
			       file.ide

**NOEKEON**

		Encryption:

			crypto -o file.noe -m noekeon -e file.bin
			crypto -o file.noe -m noekeon -k 1234567890123456 -e file.bin
			crypto -o file.noe -m noekeon -s "" -h sha1 -e file.bin
			crypto -o file.noe -m noekeon -b rsa-public.key -e file.bin
			crypto -o file.noe -m noekeon -b elgamal-public.key -e file.bin
			crypto -o file.noe -m noekeon -b naccache-public.key -e file.bin
			crypto -o file.noe -m noekeon -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.noe -m noekeon -9 public.cer -e file.bin
			crypto -o file.noe -m noekeon -9 public.pem -e file.bin
			crypto -o file.noe -m noekeon -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.noe -m noekeon -p file:"my password file.txt" -e
			       file.bin

		Decryption:

			crypto -o file.bin -m noekeon -d file.noe
			crypto -o file.bin -m noekeon -k 1234567890123456 -d file.noe
			crypto -o file.bin -m noekeon -s "" -h sha1 -d file.noe
			crypto -o file.bin -m noekeon -v rsa-private.key -d file.noe
			crypto -o file.bin -m noekeon -v elgamal-private.key -d file.noe
			crypto -o file.bin -m noekeon -v naccache-private.key -d
			       file.noe

			crypto -o file.bin -m noekeon -b ecdh-public.key -v
			       ecdh-private.key -d file.noe

			crypto -o file.bin -m noekeon -9 private.pfx -d file.noe
			crypto -o file.bin -m noekeon -9 private.pem -d file.noe
			crypto -o file.bin -m noekeon -p "my password" -s "my salt8" -d
			       file.noe

			crypto -o file.bin -m noekeon -p file:"my password file.txt" -d
			       file.noe

**TEA**

		Encryption:

			crypto -o file.tea -m tea -e file.bin
			crypto -o file.tea -m tea -k 1234567890123456 -e file.bin
			crypto -o file.tea -m tea -s "" -h sha1 -e file.bin
			crypto -o file.tea -m tea -b rsa-public.key -e file.bin
			crypto -o file.tea -m tea -b elgamal-public.key -e file.bin
			crypto -o file.tea -m tea -b naccache-public.key -e file.bin
			crypto -o file.tea -m tea -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.tea -m tea -9 public.cer -e file.bin
			crypto -o file.tea -m tea -9 public.pem -e file.bin
			crypto -o file.tea -m tea -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.tea -m tea -p file:"my password file.txt" -e
			       file.bin

		Decryption:

			crypto -o file.bin -m tea -d file.tea
			crypto -o file.bin -m tea -k 1234567890123456 -d file.tea
			crypto -o file.bin -m tea -s "" -h sha1 -d file.tea
			crypto -o file.bin -m tea -v rsa-private.key -d file.tea
			crypto -o file.bin -m tea -v elgamal-private.key -d file.tea
			crypto -o file.bin -m tea -v naccache-private.key -d file.tea
			crypto -o file.bin -m tea -b ecdh-public.key -v
			       ecdh-private.key -d file.tea

			crypto -o file.bin -m tea -9 private.pfx -d file.tea
			crypto -o file.bin -m tea -9 private.pem -d file.tea
			crypto -o file.bin -m tea -p "my password" -s "my salt8" -d
			       file.tea

			crypto -o file.bin -m tea -p file:"my password file.txt" -d
			       file.tea

**XTEA**

 		Encryption:

			crypto -o file.xtea -m xtea -e file.bin
			crypto -o file.xtea -m xtea -k 1234567890123456 -e file.bin
			crypto -o file.xtea -m xtea -s "" -h sha1 -e file.bin
			crypto -o file.xtea -m xtea -b rsa-public.key -e file.bin
			crypto -o file.xtea -m xtea -b elgamal-public.key -e file.bin
			crypto -o file.xtea -m xtea -b naccache-public.key -e file.bin
			crypto -o file.xtea -m xtea -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.xtea -m xtea -9 public.cer -e file.bin
			crypto -o file.xtea -m xtea -9 public.pem -e file.bin
			crypto -o file.xtea -m xtea -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.xtea -m xtea -p file:"my password file.txt" -e
			       file.bin

		Decryption:

			crypto -o file.bin -m xtea -d file.xtea
			crypto -o file.bin -m xtea -k 1234567890123456 -d file.xtea
			crypto -o file.bin -m xtea -s "" -h sha1 -d file.xtea
			crypto -o file.bin -m xtea -v rsa-private.key -d file.xtea
			crypto -o file.bin -m xtea -v elgamal-private.key -d file.xtea
			crypto -o file.bin -m xtea -v naccache-private.key -d file.xtea
			crypto -o file.bin -m xtea -b ecdh-public.key -v
			       ecdh-private.key -d file.xtea

			crypto -o file.bin -m xtea -9 private.pfx -d file.xtea
			crypto -o file.bin -m xtea -9 private.pem -d file.xtea
			crypto -o file.bin -m xtea -p "my password" -s "my salt8" -d
			       file.xtea

			crypto -o file.bin -m xtea -p file:"my password file.txt" -d
			       file.xtea

**GOST**

		Encryption:

			crypto -o file.gost -m gost -e file.bin
			crypto -o file.gost -m gost -k 12345678901234567890123456789012
			       -e file.bin

			crypto -o file.gost -m gost -b rsa-public.key -e file.bin
			crypto -o file.gost -m gost -b elgamal-public.key -e file.bin
			crypto -o file.gost -m gost -b naccache-public.key -e file.bin
			crypto -o file.gost -m gost -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.gost -m gost -9 public.cer -e file.bin
			crypto -o file.gost -m gost -9 public.pem -e file.bin
			crypto -o file.gost -m gost -s "" -h sha1 -e file.bin
			crypto -o file.gost -m gost -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.gost -m gost -p file:"my password file.txt" -e
			       file.bin

			crypto -o file.gost -m gost --gost-box iv -e file.bin


 		Decryption:

			crypto -o file.bin -m gost -d file.gost
			crypto -o file.bin -m gost -k 12345678901234567890123456789012
			       -d file.gost

			crypto -o file.bin -m gost -v rsa-private.key -d file.gost
			crypto -o file.bin -m gost -v elgamal-private.key -d file.gost
			crypto -o file.bin -m gost -v naccache-private.key -d file.gost
			crypto -o file.bin -m gost -b ecdh-public.key -v
			       ecdh-private.key -d file.gost

			crypto -o file.bin -m gost -9 private.pfx -d file.gost
			crypto -o file.bin -m gost -9 private.pem -d file.gost
			crypto -o file.bin -m gost -s "" -h sha1 -d file.gost
			crypto -o file.bin -m gost -p "my password" -s "my salt8" -d
			       file.gost

			crypto -o file.bin -m gost -p file:"my password file.txt" -d
			       file.gost

			crypto -o file.bin -m gost --gost-box iv -d file.gost

**SEED**

		Encryption:

			crypto -o file.seed -m seed -e file.bin
			crypto -o file.seed -m seed -k 1234567890123456 -e file.bin
			crypto -o file.seed -m seed -s "" -h sha1 -e file.bin
			crypto -o file.seed -m seed -b rsa-public.key -e file.bin
			crypto -o file.seed -m seed -b elgamal-public.key -e file.bin
			crypto -o file.seed -m seed -b naccache-public.key -e file.bin
			crypto -o file.seed -m seed -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.seed -m seed -9 public.cer -e file.bin
			crypto -o file.seed -m seed -9 public.pem -e file.bin
			crypto -o file.seed -m seed -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.seed -m seed -p file:"my password file.txt" -e
			       file.bin

				   
		Decryption:

			crypto -o file.bin -m seed -d file.seed
			crypto -o file.bin -m seed -k 1234567890123456 -d file.seed
			crypto -o file.bin -m seed -s "" -h sha1 -d file.seed
			crypto -o file.bin -m seed -v rsa-private.key -d file.seed
			crypto -o file.bin -m seed -v elgamal-private.key -d file.seed
			crypto -o file.bin -m seed -v naccache-private.key -d file.seed
			crypto -o file.bin -m seed -b ecdh-public.key -v
			       ecdh-private.key -d file.seed

			crypto -o file.bin -m seed -9 private.pfx -d file.seed
			crypto -o file.bin -m seed -9 private.pem -d file.seed
			crypto -o file.bin -m seed -p "my password" -s "my salt8" -d
			       file.seed

			crypto -o file.bin -m seed -p file:"my password file.txt" -d
			       file.seed

**SKIPJACK**

 		Encryption:

			crypto -o file.sj -m skipjack -e file.bin
			crypto -o file.sj -m skipjack -k 1234567890123456 -e file.bin
			crypto -o file.sj -m skipjack -s "" -h sha1 -e file.bin
			crypto -o file.sj -m skipjack -b rsa-public.key -e file.bin
			crypto -o file.sj -m skipjack -b elgamal-public.key -e file.bin
			crypto -o file.sj -m skipjack -b naccache-public.key -e file.bin
			crypto -o file.sj -m skipjack -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.sj -m skipjack -9 public.cer -e file.bin
			crypto -o file.sj -m skipjack -9 public.pem -e file.bin
			crypto -o file.sj -m skipjack -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.sj -m skipjack -p file:"my password file.txt" -e
			       file.bin


		Decryption:

			crypto -o file.bin -m skipjack -d file.sj
			crypto -o file.bin -m skipjack -k 1234567890123456 -d file.sj
			crypto -o file.bin -m skipjack -s "" -h sha1 -d file.sj
			crypto -o file.bin -m skipjack -v rsa-private.key -d file.sj
			crypto -o file.bin -m skipjack -v elgamal-private.key -d file.sj
			crypto -o file.bin -m skipjack -v naccache-private.key -d
			       file.sj

			crypto -o file.bin -m skipjack -b ecdh-public.key -v
			       ecdh-private.key -d file.sj

			crypto -o file.bin -m skipjack -9 private.pfx -d file.sj
			crypto -o file.bin -m skipjack -9 private.pem -d file.sj
			crypto -o file.bin -m skipjack -p "my password" -s "my salt8"
			       -d file.sj

			crypto -o file.bin -m skipjack -p file:"my password file.txt"
			       -d file.sj

**RC4**

		Encryption:

			crypto -o file.rc4 -m rc4 -e file.bin
			crypto -o file.rc4 -m rc4 -b rsa-public.key -e file.bin
			crypto -o file.rc4 -m rc4 -b elgamal-public.key -e file.bin
			crypto -o file.rc4 -m rc4 -b naccache-public.key -e file.bin
			crypto -o file.rc4 -m rc4 -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.rc4 -m rc4 -9 public.cer -e file.bin
			crypto -o file.rc4 -m rc4 -9 public.pem -e file.bin
			crypto -o file.rc4 -m rc4 -y 128 -k 1234567890123456 -e file.bin
			crypto -o file.rc4 -m rc4 -s "" -h sha1 -e file.bin
			crypto -o file.rc4 -m rc4 -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.rc4 -m rc4 -p file:"my password file.txt" -e
			       file.bin


 		Decryption:

			crypto -o file.bin -m rc4 -d file.rc4
			crypto -o file.bin -m rc4 -v rsa-private.key -d file.rc4
			crypto -o file.bin -m rc4 -v elgamal-private.key -d file.rc4
			crypto -o file.bin -m rc4 -v naccache-private.key -d file.rc4
			crypto -o file.bin -m rc4 -b ecdh-public.key -v
			       ecdh-private.key -d file.rc4

			crypto -o file.bin -m rc4 -9 private.pfx -d file.rc4
			crypto -o file.bin -m rc4 -9 private.pem -d file.rc4
			crypto -o file.bin -m rc4 -y 128 -k 1234567890123456 -d file.rc4
			crypto -o file.bin -m rc4 -s "" -h sha1 -d file.rc4
			crypto -o file.bin -m rc4 -p "my password" -s "my salt8" -d
			       file.rc4

			crypto -o file.bin -m rc4 -p file:"my password file.txt" -d
			       file.rc4

**RC5**

		Encryption:

			crypto -o file.rc5 -m rc5 -e file.bin
			crypto -o file.rc5 -m rc5 -e -4 -5 255 -e file.bin
			crypto -o file.rc5 -m rc5 -b rsa-public.key -e file.bin
			crypto -o file.rc5 -m rc5 -b elgamal-public.key -e file.bin
			crypto -o file.rc5 -m rc5 -b naccache-public.key -e file.bin
			crypto -o file.rc5 -m rc5 -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.rc5 -m rc5 -9 public.cer -e file.bin
			crypto -o file.rc5 -m rc5 -9 public.pem -e file.bin
			crypto -o file.rc5 -m rc5 -k 1234567890123456 -e file.bin
			crypto -o file.rc5 -m rc5 -s "" -h sha1 -e file.bin
			crypto -o file.rc5 -m rc5 -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.rc5 -m rc5 -p file:"my password file.txt" -e
			       file.bin


		Decryption:

			crypto -o file.bin -m rc5 -d file.rc5
			crypto -o file.bin -m rc5 -e -4 -5 255 -d file.rc5
			crypto -o file.bin -m rc5 -v rsa-private.key -d file.rc5
			crypto -o file.bin -m rc5 -v elgamal-private.key -d file.rc5
			crypto -o file.bin -m rc5 -v naccache-private.key -d file.rc5
			crypto -o file.bin -m rc5 -b ecdh-public.key -v
			       ecdh-private.key -d file.rc5

			crypto -o file.bin -m rc5 -9 private.pfx -d file.rc5
			crypto -o file.bin -m rc5 -9 private.pem -d file.rc5
			crypto -o file.bin -m rc5 -k 1234567890123456 -d file.rc5
			crypto -o file.bin -m rc5 -s "" -h sha1 -d file.rc5
			crypto -o file.bin -m rc5 -p "my password" -s "my salt8" -d
			       file.rc5

			crypto -o file.bin -m rc5 -p file:"my password file.txt" -d
			       file.rc5

**RC6**

 		Encryption:

			crypto -o file.rc6 -m rc6 -e file.bin
			crypto -o file.rc6 -m rc6 -b rsa-public.key -e file.bin
			crypto -o file.rc6 -m rc6 -b elgamal-public.key -e file.bin
			crypto -o file.rc6 -m rc6 -b naccache-public.key -e file.bin
			crypto -o file.rc6 -m rc6 -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.rc6 -m rc6 -9 public.cer -e file.bin
			crypto -o file.rc6 -m rc6 -9 public.pem -e file.bin
			crypto -o file.rc6 -m rc6 -k 1234567890123456 -e file.bin
			crypto -o file.rc6 -m rc6 -s "" -h sha1 -e file.bin
			crypto -o file.rc6 -m rc6 -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.rc6 -m rc6 -p file:"my password file.txt" -e
			       file.bin


 		Decryption:

			crypto -o file.bin -m rc6 -d file.rc6
			crypto -o file.bin -m rc6 -v rsa-private.key -d file.rc6
			crypto -o file.bin -m rc6 -v elgamal-private.key -d file.rc6
			crypto -o file.bin -m rc6 -v naccache-private.key -d file.rc6
			crypto -o file.bin -m rc6 -b ecdh-public.key -v
			       ecdh-private.key -d file.rc6

			crypto -o file.bin -m rc6 -9 private.pfx -d file.rc6
			crypto -o file.bin -m rc6 -9 private.pem -d file.rc6
			crypto -o file.bin -m rc6 -k 1234567890123456 -d file.rc6
			crypto -o file.bin -m rc6 -s "" -h sha1 -d file.rc6
			crypto -o file.bin -m rc6 -p "my password" -s "my salt8" -d
			       file.rc6

			crypto -o file.bin -m rc6 -p file:"my password file.txt" -d
			       file.rc6

**HC**

		Encryption:

			crypto -o file.hc -m hc -e file.bin
			crypto -o file.hc -m hc -b rsa-public.key -e file.bin
			crypto -o file.hc -m hc -b elgamal-public.key -e file.bin
			crypto -o file.hc -m hc -b naccache-public.key -e file.bin
			crypto -o file.hc -m hc -b ecdh-public.key -v ecdh-private.key
			       -e file.bin

			crypto -o file.hc -m hc -9 public.cer -e file.bin
			crypto -o file.hc -m hc -9 public.pem -e file.bin
			crypto -o file.hc -m hc -y 128 -k 1234567890123456 -e file.bin
			crypto -o file.hc -m hc -s "" -h sha1 -e file.bin
			crypto -o file.hc -m hc -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.hc -m hc -p file:"my password file.txt" -e
			       file.bin
				   

		Decryption:

			crypto -o file.bin -m hc -d file.hc
			crypto -o file.bin -m hc -v rsa-private.key -d file.hc
			crypto -o file.bin -m hc -v elgamal-private.key -d file.hc
			crypto -o file.bin -m hc -v naccache-private.key -d file.hc
			crypto -o file.bin -m hc -b ecdh-public.key -v ecdh-private.key
			       -d file.hc

			crypto -o file.bin -m hc -9 private.pfx -d file.hc
			crypto -o file.bin -m hc -9 private.pem -d file.hc
			crypto -o file.bin -m hc -y 128 -k 1234567890123456 -d file.hc
			crypto -o file.bin -m hc -s "" -h sha1 -d file.hc
			crypto -o file.bin -m hc -p "my password" -s "my salt8" -d
			       file.hc

			crypto -o file.bin -m hc -p file:"my password file.txt" -d
			       file.hc

**ISAAC**

		Encryption:

			crypto -o file.isa -m isaac -e file.bin
			crypto -o file.isa -m isaac -b rsa-public.key -e file.bin
			crypto -o file.isa -m isaac -b elgamal-public.key -e file.bin
			crypto -o file.isa -m isaac -b naccache-public.key -e file.bin
			crypto -o file.isa -m isaac -b ecdh-public.key -v
			       ecdh-private.key -e file.bin

			crypto -o file.isa -m isaac -9 public.cer -e file.bin
			crypto -o file.isa -m isaac -9 public.pem -e file.bin
			crypto -o file.isa -m isaac -y 8192 -e file.bin
			crypto -o file.isa -m isaac -s "" -h sha1 -e file.bin
			crypto -o file.isa -m isaac -p "my password" -s "my salt8" -e
			       file.bin

			crypto -o file.isa -m isaac -p file:"my password file.txt" -e
			       file.bin


		Decryption:

			crypto -o file.bin -m isaac -d file.isa
			crypto -o file.bin -m isaac -v rsa-private.key -d file.isa
			crypto -o file.bin -m isaac -v elgamal-private.key -d file.isa
			crypto -o file.bin -m isaac -v naccache-private.key -d file.isa
			crypto -o file.bin -m isaac -b ecdh-public.key -v
			       ecdh-private.key -d file.isa

			crypto -o file.bin -m isaac -9 private.pfx -d file.isa
			crypto -o file.bin -m isaac -9 private.pem -d file.isa
			crypto -o file.bin -m isaac -y 8192 -d file.isa
			crypto -o file.bin -m isaac -s "" -h sha1 -d file.isa
			crypto -o file.bin -m isaac -p "my password" -s "my salt8" -d
			       file.isa

			crypto -o file.bin -m isaac -p file:"my password file.txt" -d
			       file.isa

**ECIES**

		Key pair generation:

			crypto -m ecies -g -b public.key -v private.key --curve prime256v1
			crypto -m ecies -g -b public.key -v private.key --curve-store x962
			       --curve prime256v1

				   
		Encryption:

			crypto -o file.ies -m ecies -b public.key -v private.key -e
			       file.bin

			crypto -o file.ies -m ecies -b public.key -v private.key -h
			       sha1 --ies-cipher rijndael -y 128 -l 128 -e file.bin


		Decryption:

			crypto -o file.bin -m ecies -b public.key -v private.key -d
			       file.ies

			crypto -o file.bin -m ecies -b public.key -v private.key -h
			       sha1 --ies-cipher rijndael -y 128 -l 128 -d file.ies

**DLIES**

		Key pair generation:

			crypto -m dlies -g -b public.key -v private.key
			crypto -m dlies -g -b public.key -v private.key -y 1024
			       --certainty 8


		Encryption:

			crypto -o file.ies -m dlies -b public.key -v private.key -e
			       file.bin

			crypto -o file.ies -m dlies -b public.key -v private.key -h
			       sha1 --ies-cipher rijndael -y 128 -l 128 -e file.bin


		Decryption:

			crypto -o file.bin -m dlies -b public.key -v private.key -d
			       file.ies

			crypto -o file.bin -m dlies -b public.key -v private.key -h
			       sha1 --ies-cipher rijndael -y 128 -l 128 -d file.ies

**RSA**

		Key pair generation:

			crypto -m rsa -g -b public.key -v private.key
			crypto -m rsa -g -b public.key -v private.key -y 2048 -6 128
			crypto -m rsa -g -f xml -b public-key.xml -v private-key.xml
			crypto -m rsa -g --rsa-bouncy-castle -b public.key -v
			       private.key

			crypto -m rsa -g -y 2048 --rsa-bouncy-castle --certainty 20
			       --public-exponent 17 -b public.key -v private.key


		Encryption:

			crypto -o file.rsa -m rsa -b public.key -e file.bin
			crypto -o file.rsa -m rsa -b public-key.xml -a -e file.bin
			crypto -o file.rsa -m rsa -u -b pgp-public.key -e file.bin
			crypto -o file.rsa -m rsa -9 file.pem -e file.bin
			crypto -o file.rsa -m rsa -9 file.cer -e -a file.bin
			crypto -o file.rsa -m rsa -0 "my certificate common-name" -e
			       file.bin

			crypto -o file.rsa -m rsa --rsa-bouncy-castle -b public.key -e
			       file.bin

			crypto -o file.rsa -m rsa --signature file.sig -v private.key
			       -e file.bin

			crypto -o file.rsa -m rsa --signature pss file.sig -h sha1 -v
			       private.key -e file.bin

			crypto -o file.rsa -m rsa --rsa-bouncy-castle --signature
			       file.sig -a -h sha1 -v private.key -e file.bin


		Decryption:

			crypto -o file.bin -m rsa -b private.key -d file.rsa
			crypto -o file.bin -m rsa -v private-key.xml -a -d file.rsa
			crypto -o file.bin -m rsa -u -v pgp-private.key -d file.rsa
			crypto -o file.bin -m rsa -9 file.pem -d file.rsa
			crypto -o file.bin -m rsa -9 file.pfx -p "my password" -a -d
			       file.rsa

			crypto -o file.bin -m rsa --rsa-bouncy-castle -b private.key -d
			       file.rsa

			crypto -o file.bin -m rsa --signature file.sig -v private.key
			       -d file.rsa

			crypto -o file.bin -m rsa --signature pss file.sig -h sha1 -v
			       private.key -d file.rsa

			crypto -o file.bin -m rsa --rsa-bouncy-castle --signature
			       file.sig -a -h sha1 -v private.key -d file.rsa

					
**PGP**

		Key pair generation:

			crypto -m pgp -g -b public.key -v private.key -y 2048 --pgp-sha1
			crypto -m pgp -g -f armored -b public.asc -v private.asc -q 2fish
			crypto -m pgp -g -b public.key -v private.key --pgp-id "My Name
			       <my@email.com>"

			crypto -m pgp -g -y 2048 --rsa-bouncy-castle --public-exponent 17
			       --certainty 80 -b public.key -v private.key

			crypto -m pgp --pgp-algorithm elgamal -g -b public.key -v 
			       private.key

			crypto -m pgp --pgp-algorithm elgamal --pgp-master ecdsa
			       --curve-store x962 --curve prime256v1 -g -b public.key
			       -v private.key

			crypto -m pgp --pgp-algorithm elgamal --pgp-master rsa -g -b
			       public.key -v private.key

			crypto -m pgp --pgp-algorithm ecdh -y 256 -g -b public.key -v
			       private.key

			crypto -m pgp --pgp-algorithm ecdh -y 192 --pgp-master dsa -g  -b
			       public.key -v private.key

			crypto -m pgp --pgp-algorithm ecdh --curve prime256v1 -g -b 
			       public.key -v private.key


 		Encryption:

			crypto -o file.pgp -m pgp -b public.key -q safer -e file.bin
			crypto -o file.pgp -m pgp -b public.key --pgp-compress zlib -e 
			       file.bin

			crypto -o file.pgp -m pgp -f armored -b public.asc -e file.bin
			crypto -o file.pgp -m pgp -u -b rsa-public.key -e file.bin
			crypto -o file.pgp -m pgp --pgp-algorithm elgamal -u -b
			       elgamal-public.key -e file.bin

			crypto -o file.pgp -m pgp -9 file.pem -e file.bin
			crypto -o file.pgp -m pgp -9 file.cer -e file.bin
			crypto -o file.pgp -m pgp -0 "my certificate common-name" -e file.bin
			crypto -o file.pgp -m pgp --pgp-signature -u -v rsa-private.key
			       -e file.bin

			crypto -o file.pgp -m pgp --pgp-signature -9 file.pfx -e file.bin
			crypto -o file.pgp -m pgp --pgp-signature -9 public.pem -9
			       private.pem -e file.bin

			crypto -o file.pgp -m pgp --pgp-signature -9 private:
			       private.pem -9 public: public.pem -e file.bin

			crypto -o file.pgp -m pgp --pgp-signature -b public.key -v
			       private.key -e file.bin

		Decryption:

			crypto -o file.bin -m pgp -v private.key -d file.pgp
			crypto -o file.bin -m pgp -v private.asc -d file.pgp
			crypto -o file.bin -m pgp -u -v rsa-private.key -d file.pgp
			crypto -o file.bin -m pgp --pgp-algorithm elgamal -u -b
			       elgamal-public.key -v elgamal-private.key -d file.pgp

			crypto -o file.bin -m pgp -9 file.pem -d file.pgp
			crypto -o file.bin -m pgp -9 file.pfx -p "my password" -d
			       file.pgp

			crypto -o file.bin -m pgp --pgp-signature -u -v rsa-private.key
			       -d file.pgp

			crypto -o file.bin -m pgp --pgp-signature -9 file.pfx -d
			       file.pgp

			crypto -o file.bin -m pgp --pgp-signature -9 private.pem -9
			       public.pem -d file.pgp

			crypto -o file.bin -m pgp --pgp-signature -9 public: public.pem
			       -9 private: private.pem -d file.pgp

			crypto -o file.bin -m pgp --pgp-signature -v private.key -b
			       public.key -d file.pgp

**ELGAMAL**

		Key pair generation:

			crypto -m elgamal -g -b public.key -v private.key
			crypto -m elgamal -g -b public.key -v private.key -y 1024
			crypto -m elgamal -g --certainty 80 -b public.key -v private.key

		Encryption:

			crypto -o file.elg -m elgamal -b public.key -e file.bin
			crypto -o file.elg -m elgamal -b public.key -a -e file.bin
			crypto -o file.elg -m elgamal -b public.key -a -h sha1 -e
			       file.bin

			crypto -o file.elg -m elgamal -u -b pgp-public.key -e file.bin
			crypto -o file.elg -m elgamal --signature file.sig -h sha1 -b
			       public.key -e file.bin


		Decryption:

			crypto -o file.bin -m elgamal -v private.key -d file.elg
			crypto -o file.bin -m elgamal -v private.key -a -d file.elg
			crypto -o file.bin -m elgamal -v private.key -a -h sha1 -d
			       file.elg

			crypto -o file.bin -m elgamal -u -v pgp-private.key -d file.elg
			crypto -o file.bin -m elgamal --signature file.sig -h sha1 -v
			       private.key -d file.elg

**NACCACHE**

		Key pair generation:

			crypto -m naccache -g -b public.key -v private.key
			crypto -m naccache -g -b public.key -v private.key -y 1024
			crypto -m naccache -g -y 2048 --certainty 12 --small-primes 60
			       -b public.key -v private.key


		Encryption:

			crypto -o file.nac -m naccache -b public.key -e file.bin
			crypto -o file.nac -m naccache --signature file.sig -b
			       public.key -e file.bin


 		Decryption:

			crypto -o file.bin -m naccache -v private.key -d file.nac
			crypto -o file.bin -m naccache --signature file.sig -v
			       private.key -d file.nac

**ECDH**

		Key pair generation:

			crypto -m ecdh -g -y 256 -b public.key -v private.key
			crypto -m ecdh -g -y 521 --certainty 80 -b public.key -v
			       private.key

			crypto -m ecdh --curve-store x962 --curve prime256v1 -g -b
			       public.key -v private.key

					 
		Encryption and decryption:

			You can see any example of all symmetric ciphers, Pgp, and Ecies.

