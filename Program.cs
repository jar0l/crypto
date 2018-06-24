/*
MIT License

Copyright (c) 2018 José A. Rojo L.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
 * REFS:
 * http://blogs.msdn.com/b/shawnfa/archive/2006/10/09/the-differences-between-rijndael-and-aes.aspx
 * http://stackoverflow.com/questions/17171893/algorithm-is-the-rijndaelmanaged-class-in-c-sharp-equivalent-to-aes-encryption
 * https://cketkar.wordpress.com/2013/05/13/fips-compliance-aes-and-net-crypto/
 * http://blogs.msdn.com/b/shawnfa/archive/2004/04/14/113514.aspx
 * http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
 * http://msdn.microsoft.com/en-us/library/system.security.cryptography.paddingmode.aspx
 * http://en.wikipedia.org/wiki/Padding_(cryptography)
 * https://msdn.microsoft.com/en-us/library/system.security.cryptography.symmetricalgorithm.legalkeysizes.aspx
 * https://msdn.microsoft.com/en-us/library/system.security.cryptography.symmetricalgorithm.iv(v=vs.110).aspx
 * https://msdn.microsoft.com/es-es/library/windows/desktop/aa386986(v=vs.85).aspx
 * http://stackoverflow.com/questions/7444586/how-can-i-sign-a-file-using-rsa-and-sha256-with-net
 * http://blog.aggregatedintelligence.com/2010/02/encryptingdecrypting-using.html
 * https://support.microsoft.com/es-es/help/950090/installing-a-pfx-file-using-x509certificate-from-a-standard-.net-application
 * http://stackoverflow.com/questions/13231858/private-key-of-certificate-in-certificate-store-not-readable
 * https://msdn.microsoft.com/es-es/library/system.security.cryptography.x509certificates.x509certificate2(v=vs.110).aspx
 * http://www.bouncycastle.org/csharp/
 * https://code.msdn.microsoft.com/Pretty-Good-Privacy-using-4f473c67
 * http://bouncy-castle.1462172.n4.nabble.com/attachment/1466960/0/EncryptDecryptLargeFiles.java
 * https://crypto.stackexchange.com/questions/15449/rsa-key-generation-parameters-public-exponent-certainty-string-to-key-count/15450#15450
 * http://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test
 * https://sites.google.com/site/lcastelli/cryptolib
 * https://hashlib.codeplex.com/
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Xml.Serialization;
using System.Runtime.InteropServices;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Anssi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Custom.Sec;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities;

using CryptoLib.SymmetricAlgorithms;                                                                    // MARS

using HashLib;                                                                                          // HASHES
using HashLib.Crypto;
using HashLib.Crypto.SHA3;
using HashLib.Hash32;
using HashLib.Hash64;
using HashLib.Hash128;
using HashLib.Checksum;

using Jarol.Console;
using Jarol.IO;

namespace crypto
{
    public class Program
    {   
        private enum CryptoJob
        {
              OTHER
            , ENCRYPT
            , DECRYPT
        };

        private enum CryptoFormat
        {
              BASE64
            , XML
            , ARMORED
            , RAW
        };

        private enum CryptoPadding
        {
              PKCS7     = 2
            , Zeros     = 3
            , X923      = 4
            , ISO10126  = 5
            , ISO7816D4 = 6
            , TBC       = 7
            , OAEP      = 8
            , PKCS1     = 9
            , ISO9796D1 = 10
        };

        //----------------------------------------------------------------------------------

        private struct SymmetricKey
        {
            public byte[] key;
            public byte[] iv;
        }

        //----------------------------------------------------------------------------------

        public struct AbstractCertificate
        {
            public string target;
            public bool   store;
            public byte   type;

            public static AbstractCertificate Create (string t, bool b, byte k)
            {
                return new AbstractCertificate() { target = t, store = b, type = k };
            }
        }

        //----------------------------------------------------------------------------------

        public struct AbstractCurve
        {
            public string name;
            public string store;

            public static AbstractCurve Create (string n, string s)
            {
                return new AbstractCurve() { name = n, store = s, };
            }
        }

        //----------------------------------------------------------------------------------

        private const string MSG_PROCESSING               = "Processing. Please wait...";
        private const string MSG_INVALID_OUTPUT           = "Invalid output file or directory!";
        private const string MSG_INVALID_KEY_SIZE         = "Invalid key size!";
        private const string MSG_INVALID_BLOCK_SIZE       = "Invalid block size!";
        private const string MSG_INVALID_FEEDBACK_SIZE    = "Invalid feedback size!";
        private const string MSG_INVALID_PUBLIC_KEY       = "Invalid public key!";
        private const string MSG_INVALID_PRIVATE_KEY      = "Invalid private key!";
        private const string MSG_INVALID_KEY_PAIR         = "Invalid key pair!";
        private const string MSG_INVALID_CIPHER_MODE      = "Invalid cipher mode!";
        private const string MSG_INVALID_BUFFER_SIZE      = "Invalid buffer size!";
        private const string MSG_INVALID_PADDING_MODE     = "Invalid padding mode!";
        private const string MSG_INVALID_HASH             = "Invalid hash!";
        private const string MSG_INVALID_IV               = "The initial vector needs to be {0} bytes length!";
        private const string MSG_INVALID_KEY              = "The key needs to be {0} bytes length!";
        private const string MSG_INVALID_RADIX            = "Radix must be between 2 and 64!";
        private const string MSG_INVALID_CODE             = "Invalid length or repeated characters in the base code string!";
        private const string MSG_INVALID_BASE_SEQ         = "Invalid Base{0} sequence";
        private const string MSG_INVALID_IES_CIPHER       = "Invalid Ies cipher!";
        private const string MSG_INVALID_PGP_ALGORITHM    = "Invalid Pgp algorithm!";
        private const string MSG_INVALID_CURVE_STORE      = "Invalid curve store!";
        private const string MSG_INVALID_FORMAT           = "Invalid format!";
        private const string MSG_INVALID_HASH_KEY_SIZE    = "Can't use the {0} hash, The key has a size less than {1}!";
        private const string MSG_INVALID_RSA_KEY          = "The key type is not Rsa!";
        private const string MSG_INVALID_ELGAMAL_KEY      = "The key type is not ElGamal!";
        private const string MSG_INVALID_ECDH_KEY         = "The key type is not ECDH!";
        private const string MSG_INVALID_EXPORT_PARAMS    = "Invalid export parameters!";
        private const string MSG_NON_RECIPROCAL_KEYS      = "Non-reciprocal Pgp keys!";
        private const string MSG_IV_DOES_NOT_ALLOW        = "The current mode or operation does not allow initial vector and will not be processed!";
        private const string MSG_CER_ALG_INCOMPATIBLE     = "The use of certificates is only compatible with the RSA algorithm, other cases are ignored!";
        private const string MSG_GEN_WITH_CER_DECRYPT     = "The key pair generation can not be used simultaneously with certificates or decryption processes!";
        private const string MSG_GEN_WITH_ENCRYPT         = "The key pair generation can not be used simultaneously with the encryption indicator for this mode!";
        private const string MSG_CROSS_INCOMPATIBLE       = "The crossbreeding modifier can not be used simultaneously with key pair generation!";
        private const string MSG_CROSS_RSA_PUB_KEY        = "The public key file is not necessary, it will only be processed from the private key!";
        private const string MSG_FILE_WAS_NOT_FOUND       = "The file(s) was not found: \"{0}\"";
        private const string MSG_PROCESS_CANCELLED        = "Process cancelled by the user!\n";
        private const string MSG_DONE                     = "Done!\n";
        private const string MSG_PASSWORD                 = "You must enter at least 1 character.\n\n> Password: ";
        private const string MSG_CONFIRM_PWD              = "Confirm the password. Enter the password again.\n\n> Password: ";
        private const string MSG_SALT                     = "You must enter at least 8 characters or nothing at all.\n\n> Salt: ";
        private const string MSG_PRIVATE_KEY_PWD          = "Private key password: ";
        private const string MSG_NO_PGP_KEY_FOUND         = "No Pgp {0} key found!";
        private const string MSG_WRONG_LINE_WRAP          = "Wrong line wrap for Base{0} encode!";
        private const string MSG_CONTINUE_QUESTION        = "\n\n> Do you want to continue?";
        private const string MSG_EXPORT_PWD_QUESTION      = "Do you want to use the certificate password for Pgp private key?";
        private const string MSG_EXCEPTION_LOOPING        = "The same exception has produced more than {0} consecutive times!";
        private const string MSG_WRONG_PASSWORD           = "Wrong password! ";
        private const string MSG_WRONG_PWD_SALT           = "Wrong password or salt";
        private const string MSG_PLEASE_TRY_AGAIN         = "Please try again.";
        private const string MSG_KEYPAIR_INSECURE         = "The resulting key pair might not be secure!";
        private const string MSG_LARGE_KEYSIZE            = "The key size is considerably large, It will take a long time!";
        private const string MSG_MALFORMED_CMD_LINE       = "Malformed command line!";
        private const string MSG_PUBLIC_KEY_ONLY          = "There is only one public key!";
        private const string MSG_EXPORT_USE               = "The export modifier can not be used simultaneously with encryption, decryption, or key pair generation!";
        private const string MSG_PGP_SIGN_USE             = "The signature parameter is not necessary for decryption, exportation, or key pair generation and will not be processed!";
        private const string MSG_GENERIC_USE              = "The {0} parameter is not necessary or supported for current mode or operation and will not be processed!";
        private const string MSG_UNICODE_QUESTION         = "The string contains Unicode characters!\n\n> Do you want to keep them?";
        private const string MSG_UNICODE_CHANGE           = "The character encoding was changed to Unicode!";
        private const string MSG_INVALID_ALGO_SIGN        = "The specified algorithm key cannot be used to sign with Pgp. An DSA, RSA, or ECDSA master key is needed! You can try export keys to Pgp.";
        private const string MSG_INNER_EXCEPTION_CTRL     = "Inner exception!";
        private const string MSG_UNSUPPORTED_KEY_PROVIDER = "Key exchange provider not supported!";
        private const string FILES                        = " files.";
        private const string HASH_BLAKE224                = "BLAKE224";
        private const string HASH_BLAKE256                = "BLAKE256";
        private const string HASH_BLAKE384                = "BLAKE384";
        private const string HASH_BLAKE512                = "BLAKE512";
        private const string HASH_BMW224                  = "BMW224";
        private const string HASH_BMW256                  = "BMW256";
        private const string HASH_BMW384                  = "BMW384";
        private const string HASH_BMW512                  = "BMW512";
        private const string HASH_CUBE224                 = "CUBE224";
        private const string HASH_CUBE256                 = "CUBE256";
        private const string HASH_CUBE384                 = "CUBE384";
        private const string HASH_CUBE512                 = "CUBE512";
        private const string HASH_ECHO224                 = "ECHO224";
        private const string HASH_ECHO256                 = "ECHO256";
        private const string HASH_ECHO384                 = "ECHO384";
        private const string HASH_ECHO512                 = "ECHO512";
        private const string HASH_FUGUE224                = "FUGUE224";
        private const string HASH_FUGUE256                = "FUGUE256";
        private const string HASH_FUGUE384                = "FUGUE384";
        private const string HASH_FUGUE512                = "FUGUE512";
        private const string HASH_GROESTL224              = "GROESTL224";
        private const string HASH_GROESTL256              = "GROESTL256";
        private const string HASH_GROESTL384              = "GROESTL384";
        private const string HASH_GROESTL512              = "GROESTL512";
        private const string HASH_HAMSI224                = "HAMSI224";
        private const string HASH_HAMSI256                = "HAMSI256";
        private const string HASH_HAMSI384                = "HAMSI384";
        private const string HASH_HAMSI512                = "HAMSI512";
        private const string HASH_JH224                   = "JH224";
        private const string HASH_JH256                   = "JH256";
        private const string HASH_JH384                   = "JH384";
        private const string HASH_JH512                   = "JH512";
        private const string HASH_KECCAK224               = "KECCAK224";
        private const string HASH_KECCAK256               = "KECCAK256";
        private const string HASH_KECCAK384               = "KECCAK384";
        private const string HASH_KECCAK512               = "KECCAK512";
        private const string HASH_LUFFA224                = "LUFFA224";
        private const string HASH_LUFFA256                = "LUFFA256";
        private const string HASH_LUFFA384                = "LUFFA384";
        private const string HASH_LUFFA512                = "LUFFA512";
        private const string HASH_SHABAL224               = "SHABAL224";
        private const string HASH_SHABAL256               = "SHABAL256";
        private const string HASH_SHABAL384               = "SHABAL384";
        private const string HASH_SHABAL512               = "SHABAL512";
        private const string HASH_SHAVITE_224             = "SHAVITE224";
        private const string HASH_SHAVITE_256             = "SHAVITE256";
        private const string HASH_SHAVITE_384             = "SHAVITE384";
        private const string HASH_SHAVITE_512             = "SHAVITE512";
        private const string HASH_SIMD224                 = "SIMD224";
        private const string HASH_SIMD256                 = "SIMD256";
        private const string HASH_SIMD384                 = "SIMD384";
        private const string HASH_SIMD512                 = "SIMD512";
        private const string HASH_SKEIN224                = "SKEIN224";
        private const string HASH_SKEIN256                = "SKEIN256";
        private const string HASH_SKEIN384                = "SKEIN384";
        private const string HASH_SKEIN512                = "SKEIN512";
        private const string HASH_RIPEMD                  = "RIPEMD";
        private const string HASH_RIPEMD128               = "RIPEMD128";
        private const string HASH_RIPEMD160               = "RIPEMD160";
        private const string HASH_RIPEMD256               = "RIPEMD256";
        private const string HASH_RIPEMD320               = "RIPEMD320";
        private const string HASH_SHA224                  = "SHA224";
        private const string HASH_SHA256                  = "SHA256";
        private const string HASH_SHA384                  = "SHA384";
        private const string HASH_SHA512                  = "SHA512";
        private const string HASH_SHA1                    = "SHA1";
        private const string HASH_SHA0                    = "SHA0";
        private const string HASH_MD4                     = "MD4";
        private const string HASH_MD2                     = "MD2";
        private const string HASH_MD5                     = "MD5";
        private const string HASH_GRINDAHL256             = "GRINDAHL256";
        private const string HASH_GRINDAHL512             = "GRINDAHL512";
        private const string HASH_HAS160                  = "HAS160";
        private const string HASH_HAVAL3_128              = "HAVAL3-128";
        private const string HASH_HAVAL3_160              = "HAVAL3-160";
        private const string HASH_HAVAL3_192              = "HAVAL3-192";
        private const string HASH_HAVAL3_224              = "HAVAL3-224";
        private const string HASH_HAVAL3_256              = "HAVAL3-256";
        private const string HASH_HAVAL4_128              = "HAVAL4-128";
        private const string HASH_HAVAL4_160              = "HAVAL4-160";
        private const string HASH_HAVAL4_192              = "HAVAL4-192";
        private const string HASH_HAVAL4_224              = "HAVAL4-224";
        private const string HASH_HAVAL4_256              = "HAVAL4-256";
        private const string HASH_HAVAL5_128              = "HAVAL5-128";
        private const string HASH_HAVAL5_160              = "HAVAL5-160";
        private const string HASH_HAVAL5_192              = "HAVAL5-192";
        private const string HASH_HAVAL5_224              = "HAVAL5-224";
        private const string HASH_HAVAL5_256              = "HAVAL5-256";
        private const string HASH_PANAMA                  = "PANAMA";
        private const string HASH_RG32                    = "RG32";
        private const string HASH_RG64                    = "RG64";
        private const string HASH_SNEFRU4_128             = "SNEFRU4-128";
        private const string HASH_SNEFRU4_256             = "SNEFRU4-256";
        private const string HASH_SNEFRU8_128             = "SNEFRU8-128";
        private const string HASH_SNEFRU8_256             = "SNEFRU8-256";
        private const string HASH_TIGER2                  = "TIGER2";
        private const string HASH_TIGER3_192              = "TIGER3-192";
        private const string HASH_TIGER4_192              = "TIGER4-192";
        private const string HASH_WHIRLPOOL               = "WHIRLPOOL";
        private const string HASH_AP                      = "AP";
        private const string HASH_BERNSTEIN               = "BERNSTEIN";
        private const string HASH_BERNSTEIN1              = "BERNSTEIN1";
        private const string HASH_BKDR                    = "BKDR";
        private const string HASH_DEK                     = "DEK";
        private const string HASH_DJB                     = "DJB";
        private const string HASH_DOTNET                  = "DOTNET";
        private const string HASH_ELF                     = "ELF";
        private const string HASH_FNV                     = "FNV";
        private const string HASH_FNV1A                   = "FNV1A";
        private const string HASH_FNV64                   = "FNV64";
        private const string HASH_FNV1A64                 = "FNV1A64";
        private const string HASH_JENKINS3                = "JENKINS3";
        private const string HASH_JS                      = "JS";
        private const string HASH_MURMUR2                 = "MURMUR2";
        private const string HASH_MURMUR2_64              = "MURMUR2-64";
        private const string HASH_MURMUR3                 = "MURMUR3";
        private const string HASH_MURMUR3_128             = "MURMUR3-128";
        private const string HASH_ONEATTIME               = "ONEATTIME";
        private const string HASH_PJW                     = "PJW";
        private const string HASH_ROTATING                = "ROTATING";
        private const string HASH_RS                      = "RS";
        private const string HASH_SDBM                    = "SDBM";
        private const string HASH_SHIFTANDXOR             = "SNX";
        private const string HASH_SUPERFAST               = "SUPERFAST";
        private const string HASH_SIPHASH                 = "SIPHASH";
        private const string HASH_ADLER32                 = "ADLER32";
        private const string HASH_CRC32_IEEE              = "CRC32-IEEE";
        private const string HASH_CRC32_CASTAGNOLI        = "CRC32-CASTAGNOLI";
        private const string HASH_CRC32_KOOPMAN           = "CRC32-KOOPMAN";
        private const string HASH_CRC32_Q                 = "CRC32-Q";
        private const string HASH_CRC64_ISO               = "CRC64-ISO";
        private const string HASH_CRC64_ECMA              = "CRC64-ECMA";
        private const string MOD_SHORT_MODE               = "-m";
        private const string MOD_LONG_MODE                = "--mode";
        private const string MOD_SHORT_HASH               = "-h";
        private const string MOD_LONG_HASH                = "--hash";
        private const string MOD_SHORT_KEY_SIZE           = "-y";
        private const string MOD_LONG_KEY_SIZE            = "--key-size";
        private const string MOD_SHORT_IO_OPTIONS         = "-7";
        private const string MOD_LONG_IO_OPTIONS          = "--io-options";
        private const string MOD_LONG_EXPORT              = "--export";
        private const string MOD_LONG_HELP                = "--help";
        private const string DIGEST                       = "DIGEST";
        private const string CHECKSUM                     = "CHECKSUM";
        private const string B2                           = "B2";
        private const string B3                           = "B3";
        private const string B4                           = "B4";
        private const string B5                           = "B5";
        private const string B6                           = "B6";
        private const string B7                           = "B7";
        private const string B8                           = "B8";
        private const string B9                           = "B9";
        private const string B10                          = "B10";
        private const string B11                          = "B11";
        private const string B12                          = "B12";
        private const string B13                          = "B13";
        private const string B14                          = "B14";
        private const string B15                          = "B15";
        private const string B16                          = "B16";
        private const string B17                          = "B17";
        private const string B18                          = "B18";
        private const string B19                          = "B19";
        private const string B20                          = "B20";
        private const string B21                          = "B21";
        private const string B22                          = "B22";
        private const string B23                          = "B23";
        private const string B24                          = "B24";
        private const string B25                          = "B25";
        private const string B26                          = "B26";
        private const string B27                          = "B27";
        private const string B28                          = "B28";
        private const string B29                          = "B29";
        private const string B30                          = "B30";
        private const string B31                          = "B31";
        private const string B32                          = "B32";
        private const string B33                          = "B33";
        private const string B34                          = "B34";
        private const string B35                          = "B35";
        private const string B36                          = "B36";
        private const string B37                          = "B37";
        private const string B38                          = "B38";
        private const string B39                          = "B39";
        private const string B40                          = "B40";
        private const string B41                          = "B41";
        private const string B42                          = "B42";
        private const string B43                          = "B43";
        private const string B44                          = "B44";
        private const string B45                          = "B45";
        private const string B46                          = "B46";
        private const string B47                          = "B47";
        private const string B48                          = "B48";
        private const string B49                          = "B49";
        private const string B50                          = "B50";
        private const string B51                          = "B51";
        private const string B52                          = "B52";
        private const string B53                          = "B53";
        private const string B54                          = "B54";
        private const string B55                          = "B55";
        private const string B56                          = "B56";
        private const string B57                          = "B57";
        private const string B58                          = "B58";
        private const string B59                          = "B59";
        private const string B60                          = "B60";
        private const string B61                          = "B61";
        private const string B62                          = "B62";
        private const string B63                          = "B63";
        private const string B64                          = "B64";
        private const string BIN                          = "BIN"; 
        private const string HEX                          = "HEX";
        private const string OCTAL                        = "OCTAL";
        private const string DECIMAL                      = "DECIMAL";
        private const string AES                          = "AES";
        private const string RIJNDAEL                     = "RIJNDAEL";
        private const string TDES                         = "3DES";
        private const string DES                          = "DES";
        private const string RC2                          = "RC2";
        private const string MARS                         = "MARS";
        private const string SALSA20                      = "SALSA20";
        private const string XSALSA20                     = "XSALSA20";
        private const string CHACHA                       = "CHACHA";
        private const string VMPC                         = "VMPC";
        private const string CAMELLIA                     = "CAMELLIA";
        private const string BLOWFISH                     = "BLOWFISH";
        private const string TWOFISH                      = "2FISH";
        private const string THREEFISH                    = "3FISH";
        private const string SERPENT                      = "SERPENT";
        private const string TNEPRES                      = "TNEPRES";
        private const string CAST5                        = "CAST5";
        private const string CAST6                        = "CAST6";
        private const string IDEA                         = "IDEA";
        private const string NOEKEON                      = "NOEKEON";
        private const string TEA                          = "TEA";
        private const string XTEA                         = "XTEA";
        private const string GOST                         = "GOST";
        private const string SEED                         = "SEED";
        private const string SKIPJACK                     = "SKIPJACK";
        private const string RC6                          = "RC6";
        private const string RC5                          = "RC5";
        private const string RC4                          = "RC4";
        private const string HC                           = "HC";
        private const string ISAAC                        = "ISAAC";
        private const string RSA                          = "RSA";
        private const string PGP                          = "PGP";
        private const string ELGAMAL                      = "ELGAMAL";
        private const string NACCACHE                     = "NACCACHE";
        private const string ECIES                        = "ECIES";
        private const string DLIES                        = "DLIES";
        private const string CUSTOM                       = "CUSTOM";
        private const string ANSSI                        = "ANSSI";
        private const string TELETRUST                    = "TELETRUST";
        private const string NIST                         = "NIST";
        private const string X962                         = "X962";
        private const string SEC                          = "SEC";
        private const string DSA                          = "DSA";
        private const string ECDSA                        = "ECDSA";
        private const string ECDH                         = "ECDH";
        private const string IV                           = "IV";
        private const string ISO9796D2                    = "ISO9796D2";
        private const string PSS                          = "PSS";
        private const string CODE                         = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
        private const string BASE32                       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private const string BASE32HEX                    = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
        private const string OUT                          = "output";
        private const string RNDGEN                       = "random-gen";
        private const string RSA_BC                       = "rsa-bouncy-castle";
        private const string CURVE_STORE                  = "--curve-store";
        private const string BATCH                        = "batch:";

        //----------------------------------------------------------------------------------

        private static readonly char[] _io_options_separator = new char[] { ',' };
        private static readonly char[] _path_delimiter       = new char[] { ';' };
        
        //----------------------------------------------------------------------------------

        private static bool           _banner           = true;
        private static byte           _percent          = 100;
        private static int            _buffersize       = 1024;
        private static string         _password         = string.Empty;
        private static bool           _haspwd           = false;
        private static string         _salt             = string.Empty;
        private static bool           _saltleaking      = false;
        private static string         _hash             = HASH_SHA512;
        private static string         _key              = string.Empty;
        private static string         _iv               = string.Empty;
        private static bool           _without_iv       = false;
        private static bool           _rsa_bc           = false;
        private static string         _sign             = string.Empty;
        private static string         _rsa_sign         = RSA;
        private static short          _keysize          = -1;
        private static short          _blocksize        = -1;
        private static short          _feedbacksize     = -1;
        private static int            _iterations       = 1000;
        private static int            _rounds           = 20;
        private static CipherMode     _ciphermode       = CipherMode.CBC;
        private static CryptoPadding  _padding          = CryptoPadding.PKCS7;
        private static CryptoFormat   _format           = CryptoFormat.RAW;
        private static CryptoJob      _job              = CryptoJob.OTHER;
        private static Finder         _finder           = null;
        private static Finder.Mode    _findermode       = Finder.Mode.Basic;
        private static bool           _ignorecase       = true;
        private static bool           _recursively      = false;
        private static bool           _reverse          = false;
        private static bool           _raise            = true;
        private static bool           _raisepwd         = false;
        private static bool           _b32hex           = false;
        private static bool           _rfc4648          = true;
        private static bool           _ksa3             = false;
        private static bool           _rc5b64           = false;
        private static bool           _unesc            = false;
        private static bool           _generator        = false;
        private static bool           _overwrite        = false;
        private static bool           _crossbreeding    = false;
        private static bool           _random           = false;
        private static bool           _sha1             = false;
        private static string         _public_key       = string.Empty;
        private static string         _private_key      = string.Empty;
        private static bool           _export           = false;
        private static string         _export_pbk       = string.Empty;
        private static string         _export_pvk       = string.Empty;
        private static string         _export_pwd       = string.Empty;
        private static string         _code             = CODE;
        private static short          _charsperline     = 0;
        private static string         _pgp_algorithm    = RSA;
        private static string         _pgp_id           = string.Empty;
        private static string         _pgp_master       = RSA;
        private static bool           _pgp_sign         = false;
        private static PgpPrivateKey  _pgp_pvk          = null;
        private static PgpPublicKey   _pgp_pbk          = null;
        private static string         _ies_cipher       = AES;
        private static SymmetricKey   _sk               = new SymmetricKey();
        private static bool           _tellapart        = false;
        private static byte           _certainty        = 0;
        private static long           _public_exponent  = 0;
        private static byte           _e_cnt            = 0;
        private static int            _e_num            = 0;
        private static byte           _e_max            = 2;
        private static bool           _pathdelimiter    = true;
        private static bool           _keyexchange      = false;
        private static string         _sbox             = string.Empty;
        private static Encoding       _encoding         = Encoding.ASCII;
        private static bool           _codechanged      = false;
        private static string         _mode             = string.Empty;
        private static string         _curvestore       = string.Empty;
        private static int            _small_primes     = 30;

        private static List<AbstractCurve>       _curve = new List<AbstractCurve>();
        private static List<AbstractCertificate> _cer   = new List<AbstractCertificate>();
        private static SymmetricKeyAlgorithmTag  _ska   = SymmetricKeyAlgorithmTag.Aes256;
        private static CompressionAlgorithmTag   _cat   = CompressionAlgorithmTag.Zip;

        //----------------------------------------------------------------------------------

        private static string Prompt 
        (
              string msg
            , bool   hidden
            , short  minlen = 1
            , bool   empty  = false
        ){
            StringBuilder sb = new StringBuilder();
            Messenger.Print(Messenger.Icon.WARNING, msg);

            do
            {
                ConsoleKeyInfo ki = Console.ReadKey(true);
                byte           bk = (byte)ki.KeyChar;

                if (ki.Key == ConsoleKey.Enter && ((empty && sb.Length == 0) || sb.Length >= minlen))
                    break;

                else if (ki.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                    {
                        sb.Remove(sb.Length - 1, 1);
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        Console.Write(' ');
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                    }
                }

                else if ((bk > 31 && bk < 127) || bk > 127)
                {
                    sb.Append(ki.KeyChar);
                    Console.Write(hidden ? '*' : ki.KeyChar);
                }
            }
            while (true);

            if (msg.IndexOf('\n') != -1)
                Console.WriteLine();

            return sb.ToString();
        }

        //--------------------------------------------------------------------------------

        private static void Delay (long milliseconds)
        {
            Stopwatch w = Stopwatch.StartNew();
            while (w.ElapsedMilliseconds < milliseconds);
            w.Stop();
        }

        //--------------------------------------------------------------------------------

        private static void Progress (double current, double total, int block)
        {
            if (current == block)
                Console.Write('\n');

            _percent = (byte)Math.Floor(current / total * 100);
            block    = _percent / 10;

            StringBuilder s = new StringBuilder();

            s.Append("[");
            for (short i = 0; i < 11; ++i)
                s.Append(i <= block ? '#' : ' ');

            s.Append("]: ");
            s.Append(_percent);
            s.Append('%');

            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write(s);

            if (_percent == 100)
            {
                Program.Delay(500);
                Console.SetCursorPosition(0, Console.CursorTop);

                for (byte i = 0; i < 20; ++i)
                    Console.Write(' ');

                Console.SetCursorPosition(0, Console.CursorTop - 1);
            }
        }

        //--------------------------------------------------------------------------------

        private static void LineWrapper (Stream dest, long current, ref long total)
        {
            if (_charsperline > 0 && total > 0 && current > total)
            {
                dest.WriteByte(10);
                total += _charsperline;
            }
        }

        //--------------------------------------------------------------------------------

        private static void Write
        (
              ICryptoTransform ct
            , Stream           src
            , Stream           dest
            , bool             progressbar
        ){
            if (_charsperline > 0 && (_charsperline < 4 || _charsperline % 4 != 0))
                throw new Exception(string.Format(MSG_WRONG_LINE_WRAP, 64));

            byte[] o = new byte[ct.OutputBlockSize];
            byte[] i = new byte[ct.InputBlockSize];
            long   w = _charsperline - 1;
            long   l = src.Length;
            long   p = l - ct.InputBlockSize;
            long   c = 0;
            long   t = 0;
            int    n = 0;
            int    k = 0;

            while (c < p)
            {
                if ((n = src.Read(i, 0, i.Length)) > 0)
                {
                    Program.LineWrapper(dest, t, ref w);
                    dest.Write(o, 0, k = ct.TransformBlock(i, 0, n, o, 0));
                    
                    t += k;
                    c += n;

                    if (progressbar)
                        Program.Progress(c, l, n);
                }
            }

            if (c > 0 || (l > 0 && p < 1))
            {
                Program.LineWrapper(dest, t, ref w);

                n = src.Read(i, 0, i.Length);
                Array.Clear(o, 0, o.Length);

                o = ct.TransformFinalBlock(i, 0, n);
                dest.Write(o, 0, o.Length);

                Array.Clear(o, 0, o.Length);
                Array.Clear(i, 0, i.Length);

                if (progressbar)
                    Program.Progress(c + n, l, n);
            }
        }
        
        //--------------------------------------------------------------------------------

        private static void Base64Encode (Stream src, Stream dest, bool progressbar = true)
        {
            using (ToBase64Transform t = new ToBase64Transform())
                Program.Write(t, src, dest, progressbar);
        }

        //--------------------------------------------------------------------------------

        private static byte[] Base64Encode (byte[] data, bool progressbar = false)
        {
            using (MemoryStream dt = new MemoryStream(data))
            {
                using (MemoryStream bf = new MemoryStream())
                {
                    Program.Base64Encode(dt, bf, progressbar);
                    return bf.ToArray();
                }
            }
        }

        //--------------------------------------------------------------------------------

        private static byte[] Base64Encode (string data, bool progressbar = false)
        {
            byte[] d = _encoding.GetBytes(data);
            byte[] b = Program.Base64Encode(d, progressbar);

            Array.Clear(d, 0, d.Length);
            return b;
        }

        //--------------------------------------------------------------------------------

        private static void Base64Decode (Stream src, Stream dest, bool progressbar = true)
        {
            using (FromBase64Transform t = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces))
                Program.Write(t, src, dest, progressbar);
        }

        //--------------------------------------------------------------------------------

        private static byte[] Base64Decode (byte[] data, bool progressbar = false)
        {
            using (MemoryStream dt = new MemoryStream(data))
            {
                using (MemoryStream bf = new MemoryStream())
                {
                    Program.Base64Decode(dt, bf, progressbar);
                    return bf.ToArray();
                }
            }
        }

        //--------------------------------------------------------------------------------

        private static byte[] Base64Decode (string data, bool progressbar = false)
        {
            byte[] d = Encoding.UTF8.GetBytes(data);
            byte[] b = Program.Base64Decode(d, progressbar);

            Array.Clear(d, 0, d.Length);
            return b;
        }

        //--------------------------------------------------------------------------------

        private static bool TryBase64Decode (ref byte[] data, bool clean = true)
        {
            if (data == null || data.Length < 4)
                return false;

            try
            {
                byte[] b = Program.Base64Decode(data);

                if (clean)
                    Array.Clear(data, 0, data.Length);

                data = b;
            }

            catch (FormatException)
            {
                return false;
            }

            return true;
        }

        //--------------------------------------------------------------------------------

        private static bool IsBase64 (byte[] data)
        {
            return Program.TryBase64Decode(ref data, false);
        }

        //--------------------------------------------------------------------------------

        private static bool IsBase64 (string data)
        {
            Regex r = new Regex
            (
                  "([a-z0-9+/]{4})*([a-z0-9+/]{4}|[a-z0-9+/]{3}=|[a-z0-9+/]{2}==)$"
                , RegexOptions.IgnoreCase | RegexOptions.Multiline
            );

            return r.Matches(data.Trim()).Count > 0;
        }

        //--------------------------------------------------------------------------------

        public static void Base32Encode (Stream src, Stream dest)
        {
            if (_charsperline > 0 && _charsperline < 2)
                throw new Exception(string.Format(MSG_WRONG_LINE_WRAP, 32));

            string s = _b32hex ? BASE32HEX : BASE32;
            long   l = src.Length;
            long   n = (long)Math.Ceiling(l / 5f) * 8;
            long   w = _charsperline - 1;
            short  r = 5;
            long   c = 0;
            long   p = 0;
            byte   t = 0;
            int    b;

            while ((b = src.ReadByte()) > -1)
            {
                Program.LineWrapper(dest, c++, ref w);
                dest.WriteByte((byte)s[t | (b >> 8 - r)]);

                if (r <= 3)
                {
                    Program.LineWrapper(dest, c++, ref w);
                    dest.WriteByte((byte)s[(b >> 3 - r) & 31]);
                    r += 5;
                }

                t = (byte)((b << (r -= 3)) & 31);
                Program.Progress(++p, l, 1);
            }

            if (c != n)
            {
                Program.LineWrapper(dest, c++, ref w);
                dest.WriteByte((byte)s[t]);
            }

            while (c < n)
            {
                Program.LineWrapper(dest, c++, ref w);
                dest.WriteByte(61);
            }
        }

        //--------------------------------------------------------------------------------

        public static void Base32Decode (Stream src, Stream dest)
        {
            string e = string.Format(MSG_INVALID_BASE_SEQ + '!', 32);
            string s = _b32hex ? BASE32HEX : BASE32;
            long   l = src.Length;
            long   c = 0;
            int    r = 8;
            int    t = 0;
            byte   p = 0;
            int    n, b;

            while ((b = src.ReadByte()) > -1)
            {
                Program.Progress(++c, l, 1);

                if ((b > 6 && b < 14) || b == 32)
                    continue;

                else if (b == 61)
                {
                    if (++p > 6)
                        throw new Exception(e);
                }

                else if (p > 0)
                    throw new Exception(e);

                else
                {
                    if ((n = s.IndexOf((char)b)) < 0)
                        throw new Exception(e);

                    else if (r > 5)
                        t = t | (n << (r -= 5));

                    else
                    {
                        dest.WriteByte((byte)(t | (n >> 5 - r)));
                        t = n << (r += 3);
                    }
                }
            }
        }

        //--------------------------------------------------------------------------------

        private static bool HasRepeatedChars (string src)
        {
            for (int i = 0, l = src.Length; i < l; ++i)
                for (int j = i + 1; j < l; ++j)
                    if (src[i] == src[j]) 
                        return true;

            return false;
        }

        //--------------------------------------------------------------------------------

        private static byte GetBlockSize (byte radix)
        {
            if      (radix == 2)              radix = 8;
            else if (radix == 3)              radix = 6;
            else if (radix > 3 && radix < 7)  radix = 4;
            else if (radix > 6 && radix < 16) radix = 3;
            else                              radix = 2;

            return radix;
        }


        //--------------------------------------------------------------------------------

        private static string ByteToString (byte b, byte radix)
        {
            string s = string.Empty;

            do
            {
                s = _code[b % radix] + s;
            }
            
            while ((b = (byte)(b / radix)) > 0);

            radix = Program.GetBlockSize(radix);
            b     = (byte)s.Length;

            while (b++ < radix)
                s = _code[0] + s;

            return s;
        }

        //--------------------------------------------------------------------------------

        private static byte ByteFromBlock (byte[] b, byte radix)
        {
            byte n = 0;

            for (int c, i = 0, l = b.Length; i < l; ++i)
            {
                if ((c = _code.IndexOf((char)b[i])) < 0) throw new Exception
                (
                    string.Format
                    (
                          MSG_INVALID_BASE_SEQ + " or Wrong base-code!"
                        , radix
                    )
                );

                n = (byte)(n * radix + c);
            }

            return n;
        }

        //--------------------------------------------------------------------------------

        private static void Encode 
        (
              Stream src
            , Stream dest
            , byte   radix
        ){
            if (radix < 2)
                throw new ArgumentException(MSG_INVALID_RADIX);

            if (string.IsNullOrEmpty(_code) || _code.Length < radix || Program.HasRepeatedChars(_code))
                throw new ArgumentException(MSG_INVALID_CODE);

            int n = Program.GetBlockSize(radix);
            if (_charsperline > 0 && (_charsperline < n || _charsperline % n != 0))
                throw new Exception(string.Format(MSG_WRONG_LINE_WRAP, radix));

            byte[] b = new byte[_buffersize];
            long   l = src.Length;
            long   w = _charsperline - 1;
            long   p = 0;
            long   t = 0;

            while ((n = src.Read(b, 0, _buffersize)) > 0)
            {
                for (int i = 0; i < n; ++i)
                {
                    Program.LineWrapper(dest, t, ref w);
                    byte[] c = Encoding.ASCII.GetBytes(Program.ByteToString(b[i], radix));

                    dest.Write(c, 0, c.Length);
                    Array.Clear(c, 0, c.Length);
                    t += c.Length;
                }

                Program.Progress(p += n, l, n);
            }

            Array.Clear(b, 0, b.Length);
        }

        //--------------------------------------------------------------------------------

        private static void Decode (Stream src, Stream dest, byte radix)
        {
            if (radix < 2)
                throw new ArgumentException(MSG_INVALID_RADIX);

            if (string.IsNullOrEmpty(_code) || _code.Length < radix || Program.HasRepeatedChars(_code))
                throw new ArgumentException(MSG_INVALID_CODE);

            long   l = src.Length;
            int    n = Program.GetBlockSize(radix);
            byte[] b = new byte[n];
            long   p = 0;
            int    c = 0;
            int    x;

            while ((x = src.ReadByte()) > -1)
            {
                Program.Progress(++p, l, 1);

                if ((x > 6 && x < 14) || x == 32)
                    continue;

                if (c < n)
                    b[c++] = (byte)x;

                if (c == n)
                {
                    dest.WriteByte(Program.ByteFromBlock(b, radix));
                    c = 0;
                }
            }

            Array.Clear(b, 0, b.Length);
        }

        //----------------------------------------------------------------------------------

        private static void ValidateSize (ref short var, short value, string emsg)
        {
            if (var == -1)
                var = value;

            else if (var != value)
                throw new Exception(emsg);
        }

        //----------------------------------------------------------------------------------

        private static void ValidateBlockSize (short value)
        {
            Program.ValidateSize(ref _blocksize, value, MSG_INVALID_BLOCK_SIZE);
        }

        //----------------------------------------------------------------------------------

        private static void ValidateKeySize (short value)
        {
            Program.ValidateSize(ref _keysize, value, MSG_INVALID_KEY_SIZE);
        }

        //----------------------------------------------------------------------------------

        private static void ValidateFeedbackSize (short value)
        {
            Program.ValidateSize(ref _feedbacksize, value, MSG_INVALID_FEEDBACK_SIZE);

            if (_feedbacksize % 8 != 0)
                throw new Exception(MSG_INVALID_FEEDBACK_SIZE);
        }

        //----------------------------------------------------------------------------------

        private static void ValidateSizes (short key, short block)
        {
            Program.ValidateKeySize(key);
            Program.ValidateBlockSize(block);
        }

        //----------------------------------------------------------------------------------

        private static void ValidateSizes
        (
              ref short var
            , short     min
            , short     max
            , short     def
            , string    emsg
        ){
            if (var == -1)
                var = def;

            else if (var < min || var > max || var % 8 != 0)
                throw new Exception(emsg);
        }

        //----------------------------------------------------------------------------------

        private static void ValidateKeySize (short min, short max, short def)
        {
            Program.ValidateSizes(ref _keysize, min, max, def, MSG_INVALID_KEY_SIZE);
        }

        //----------------------------------------------------------------------------------

        private static void ValidateBlockSize (short min, short max, short def)
        {
            Program.ValidateSizes(ref _blocksize, min, max, def, MSG_INVALID_BLOCK_SIZE);
        }

        //----------------------------------------------------------------------------------
        
        private static void ValidateSizeFrom128To256 (short size)
        {
            switch (size)
            {
                case 128:
                case 192:
                case 256:
                    break;

                default:
                    throw new Exception(MSG_INVALID_KEY_SIZE);
            }
        }

        //----------------------------------------------------------------------------------

        private static void ValidateSizeFrom256to1024 (short size)
        {
            switch (size)
            {
                case 256:
                case 512:
                case 1024:
                    break;

                default:
                    throw new Exception(MSG_INVALID_KEY_SIZE);
            }
        }

        //----------------------------------------------------------------------------------

        private static void ClearSymmetricKey ()
        {
            if (_sk.key != null) Array.Clear(_sk.key, 0, _sk.key.Length);
            if (_sk.iv  != null) Array.Clear(_sk.iv, 0, _sk.iv.Length);
        }

        //----------------------------------------------------------------------------------

        private static void AssertSymmetricSizes 
        (
              ref short keysize
            , ref short blocksize
            , bool      hightdiv
        ){
            if (blocksize > 0)
            {
                if ((hightdiv && blocksize < 8) || blocksize < 4)
                    throw new Exception(MSG_INVALID_BLOCK_SIZE);

                if (((hightdiv || blocksize > 64) && blocksize % 8 != 0) || (blocksize < 128 && blocksize % 4 != 0))
                    throw new Exception(MSG_INVALID_BLOCK_SIZE);

                blocksize /= (short)((hightdiv || blocksize > 64) ? 8 : 4);
            }

            keysize /= 8;
        }

        //----------------------------------------------------------------------------------

        private static byte[] GetRandomBytes (int length)
        {
            RNGCryptoServiceProvider rg = new RNGCryptoServiceProvider();
            byte[]                   br = new byte[length];

            rg.GetNonZeroBytes(br);
            return br;
        }

        //----------------------------------------------------------------------------------

        private static byte[] GetBytes (string data)
        {
            List<byte>      l = new List<byte>();
            Regex           r = new Regex(@"\\u[0-9a-f]{4}|\\x[0-9a-f]{2}", RegexOptions.IgnoreCase);
            bool            u = _encoding == Encoding.Unicode || _encoding == Encoding.BigEndianUnicode;
            MatchCollection m = _unesc ? null : r.Matches(data);
            byte[]          b = null;

            for (int i = 0, j = 0, k = _unesc ? 0 : m.Count, n = data.Length; i < n; ++i)
            {
                if (j < k)
                {
                    Capture c = m[j].Captures[0];

                    if (c.Index == i)
                    {
                        if (!u && c.Value.Length > 2)
                        {
                            if (!Program.Question(MSG_UNICODE_QUESTION))
                                u = true;

                            else
                            {
                                _encoding    = Encoding.Unicode;
                                _codechanged = true;
                                l.Clear();

                                Messenger.Print(Messenger.Icon.WARNING, MSG_UNICODE_CHANGE);
                                return Program.GetBytes(data);
                            }
                        }

                        char[] t = new char[]
                        {
                            Convert.ToChar
                            (
                                Convert.ToInt32
                                (
                                      c.Value.Substring(2)
                                    , 16
                                )
                            )
                        };

                        l.AddRange(_encoding.GetBytes(t));
                        Array.Clear(t, 0, t.Length);

                        i += c.Value.Length - 1;
                        ++j;
                        continue;
                    }
                }

                if (!u && data[i] > 255)
                {
                    if (!Program.Question(MSG_UNICODE_QUESTION))
                        u = true;

                    else
                    {
                        _encoding    = Encoding.Unicode;
                        _codechanged = true;
                        l.Clear();

                        Messenger.Print(Messenger.Icon.WARNING, MSG_UNICODE_CHANGE);
                        return Program.GetBytes(data);
                    }
                }

                l.AddRange(_encoding.GetBytes(data[i].ToString()));
            }

            b = l.ToArray();
            l.Clear();

            return b;
        }
        
        //----------------------------------------------------------------------------------

        private static HashAlgorithm GetHashAlgorithm ()
        {
            switch (_hash)
            {
                case HASH_BLAKE224:
                    return new HashAlgorithmWrapper(new Blake224());

                case HASH_BLAKE256:
                    return new HashAlgorithmWrapper(new Blake256());

                case HASH_BLAKE384:
                    return new HashAlgorithmWrapper(new Blake384());

                case HASH_BLAKE512:
                    return new HashAlgorithmWrapper(new Blake512());

                case HASH_BMW224:
                    return new HashAlgorithmWrapper(new BlueMidnightWish224());

                case HASH_BMW256:
                    return new HashAlgorithmWrapper(new BlueMidnightWish256());

                case HASH_BMW384:
                    return new HashAlgorithmWrapper(new BlueMidnightWish384());

                case HASH_BMW512:
                    return new HashAlgorithmWrapper(new BlueMidnightWish512());

                case HASH_CUBE224:
                    return new HashAlgorithmWrapper(new CubeHash224());

                case HASH_CUBE256:
                    return new HashAlgorithmWrapper(new CubeHash256());

                case HASH_CUBE384:
                    return new HashAlgorithmWrapper(new CubeHash384());

                case HASH_CUBE512:
                    return new HashAlgorithmWrapper(new CubeHash512());

                case HASH_ECHO224:
                    return new HashAlgorithmWrapper(new Echo224());

                case HASH_ECHO256:
                    return new HashAlgorithmWrapper(new Echo256());

                case HASH_ECHO384:
                    return new HashAlgorithmWrapper(new Echo384());

                case HASH_ECHO512:
                    return new HashAlgorithmWrapper(new Echo512());

                case HASH_FUGUE224:
                    return new HashAlgorithmWrapper(new Fugue224());

                case HASH_FUGUE256:
                    return new HashAlgorithmWrapper(new Fugue256());

                case HASH_FUGUE384:
                    return new HashAlgorithmWrapper(new Fugue384());

                case HASH_FUGUE512:
                    return new HashAlgorithmWrapper(new Fugue512());

                case HASH_GROESTL224:
                    return new HashAlgorithmWrapper(new Groestl224());

                case HASH_GROESTL256:
                    return new HashAlgorithmWrapper(new Groestl256());

                case HASH_GROESTL384:
                    return new HashAlgorithmWrapper(new Groestl384());

                case HASH_GROESTL512:
                    return new HashAlgorithmWrapper(new Groestl512());

                case HASH_HAMSI224:
                    return new HashAlgorithmWrapper(new Hamsi224());

                case HASH_HAMSI256:
                    return new HashAlgorithmWrapper(new Hamsi256());

                case HASH_HAMSI384:
                    return new HashAlgorithmWrapper(new Hamsi384());

                case HASH_HAMSI512:
                    return new HashAlgorithmWrapper(new Hamsi512());

                case HASH_JH224:
                    return new HashAlgorithmWrapper(new JH224());

                case HASH_JH256:
                    return new HashAlgorithmWrapper(new JH256());

                case HASH_JH384:
                    return new HashAlgorithmWrapper(new JH384());

                case HASH_JH512:
                    return new HashAlgorithmWrapper(new JH512());

                case HASH_KECCAK224:
                    return new HashAlgorithmWrapper(new Keccak224());

                case HASH_KECCAK256:
                    return new HashAlgorithmWrapper(new Keccak256());

                case HASH_KECCAK384:
                    return new HashAlgorithmWrapper(new Keccak384());

                case HASH_KECCAK512:
                    return new HashAlgorithmWrapper(new Keccak512());

                case HASH_LUFFA224:
                    return new HashAlgorithmWrapper(new Luffa224());

                case HASH_LUFFA256:
                    return new HashAlgorithmWrapper(new Luffa256());

                case HASH_LUFFA384:
                    return new HashAlgorithmWrapper(new Luffa384());

                case HASH_LUFFA512:
                    return new HashAlgorithmWrapper(new Luffa512());

                case HASH_SHABAL224:
                    return new HashAlgorithmWrapper(new Shabal224());

                case HASH_SHABAL256:
                    return new HashAlgorithmWrapper(new Shabal256());

                case HASH_SHABAL384:
                    return new HashAlgorithmWrapper(new Shabal384());

                case HASH_SHABAL512:
                    return new HashAlgorithmWrapper(new Shabal512());

                case HASH_SHAVITE_224:
                    return new HashAlgorithmWrapper(new SHAvite3_224());

                case HASH_SHAVITE_256:
                    return new HashAlgorithmWrapper(new SHAvite3_256());

                case HASH_SHAVITE_384:
                    return new HashAlgorithmWrapper(new SHAvite3_384());

                case HASH_SHAVITE_512:
                    return new HashAlgorithmWrapper(new SHAvite3_512());

                case HASH_SIMD224:
                    return new HashAlgorithmWrapper(new SIMD224());

                case HASH_SIMD256:
                    return new HashAlgorithmWrapper(new SIMD256());

                case HASH_SIMD384:
                    return new HashAlgorithmWrapper(new SIMD384());

                case HASH_SIMD512:
                    return new HashAlgorithmWrapper(new SIMD512());

                case HASH_SKEIN224:
                    return new HashAlgorithmWrapper(new Skein224());

                case HASH_SKEIN256:
                    return new HashAlgorithmWrapper(new Skein256());

                case HASH_SKEIN384:
                    return new HashAlgorithmWrapper(new Skein384());

                case HASH_SKEIN512:
                    return new HashAlgorithmWrapper(new Skein512());

                case HASH_RIPEMD:
                    return new HashAlgorithmWrapper(new RIPEMD());

                case HASH_RIPEMD128:
                    return new HashAlgorithmWrapper(new RIPEMD128());

                case HASH_RIPEMD160:
                    return RIPEMD160.Create();

                case HASH_RIPEMD256:
                    return new HashAlgorithmWrapper(new RIPEMD256());

                case HASH_RIPEMD320:
                    return new HashAlgorithmWrapper(new RIPEMD320());

                case HASH_SHA512:
                    return SHA512.Create();

                case HASH_SHA384:
                    return SHA384.Create();

                case HASH_SHA256:
                    return SHA256.Create();

                case HASH_SHA224:
                    return new HashAlgorithmWrapper(new SHA224());

                case HASH_SHA1:
                    return SHA1.Create();

                case HASH_SHA0:
                    return new HashAlgorithmWrapper(new SHA0());

                case HASH_MD5:
                    return MD5.Create();

                case HASH_MD4:
                    return new HashAlgorithmWrapper(new MD4());

                case HASH_MD2:
                    return new HashAlgorithmWrapper(new MD2());

                case GOST:
                    return new HashAlgorithmWrapper(new Gost());

                case HASH_GRINDAHL256:
                    return new HashAlgorithmWrapper(new Grindahl256());

                case HASH_GRINDAHL512:
                    return new HashAlgorithmWrapper(new Grindahl512());

                case HASH_HAS160:
                    return new HashAlgorithmWrapper(new HAS160());

                case HASH_HAVAL3_128:
                    return new HashAlgorithmWrapper(new Haval_3_128());

                case HASH_HAVAL3_160:
                    return new HashAlgorithmWrapper(new Haval_3_160());

                case HASH_HAVAL3_192:
                    return new HashAlgorithmWrapper(new Haval_3_192());

                case HASH_HAVAL3_224:
                    return new HashAlgorithmWrapper(new Haval_3_224());

                case HASH_HAVAL3_256:
                    return new HashAlgorithmWrapper(new Haval_3_256());

                case HASH_HAVAL4_128:
                    return new HashAlgorithmWrapper(new Haval_4_128());

                case HASH_HAVAL4_160:
                    return new HashAlgorithmWrapper(new Haval_4_160());

                case HASH_HAVAL4_192:
                    return new HashAlgorithmWrapper(new Haval_4_192());

                case HASH_HAVAL4_224:
                    return new HashAlgorithmWrapper(new Haval_4_224());

                case HASH_HAVAL4_256:
                    return new HashAlgorithmWrapper(new Haval_4_256());

                case HASH_HAVAL5_128:
                    return new HashAlgorithmWrapper(new Haval_5_128());

                case HASH_HAVAL5_160:
                    return new HashAlgorithmWrapper(new Haval_5_160());

                case HASH_HAVAL5_192:
                    return new HashAlgorithmWrapper(new Haval_5_192());

                case HASH_HAVAL5_224:
                    return new HashAlgorithmWrapper(new Haval_5_224());

                case HASH_HAVAL5_256:
                    return new HashAlgorithmWrapper(new Haval_5_256());

                case HASH_PANAMA:
                    return new HashAlgorithmWrapper(new Panama());

                case HASH_RG32:
                    return new HashAlgorithmWrapper(new RadioGatun32());

                case HASH_RG64:
                    return new HashAlgorithmWrapper(new RadioGatun64());

                case HASH_SNEFRU4_128:
                    return new HashAlgorithmWrapper(new Snefru_4_128());

                case HASH_SNEFRU4_256:
                    return new HashAlgorithmWrapper(new Snefru_4_256());

                case HASH_SNEFRU8_128:
                    return new HashAlgorithmWrapper(new Snefru_8_128());

                case HASH_SNEFRU8_256:
                    return new HashAlgorithmWrapper(new Snefru_8_256());

                case HASH_TIGER2:
                    return new HashAlgorithmWrapper(new Tiger2());

                case HASH_TIGER3_192:
                    return new HashAlgorithmWrapper(new Tiger_3_192());

                case HASH_TIGER4_192:
                    return new HashAlgorithmWrapper(new Tiger_4_192());

                case HASH_WHIRLPOOL:
                    return new HashAlgorithmWrapper(new Whirlpool());

                case HASH_AP:
                    return new HashAlgorithmWrapper(new AP());

                case HASH_BERNSTEIN:
                    return new HashAlgorithmWrapper(new Bernstein());

                case HASH_BERNSTEIN1:
                    return new HashAlgorithmWrapper(new Bernstein1());

                case HASH_BKDR:
                    return new HashAlgorithmWrapper(new BKDR());

                case HASH_DEK:
                    return new HashAlgorithmWrapper(new DEK());

                case HASH_DJB:
                    return new HashAlgorithmWrapper(new DJB());

                case HASH_DOTNET:
                    return new HashAlgorithmWrapper(new DotNet());

                case HASH_ELF:
                    return new HashAlgorithmWrapper(new ELF());

                case HASH_FNV:
                    return new HashAlgorithmWrapper(new FNV());

                case HASH_FNV1A:
                    return new HashAlgorithmWrapper(new FNV1a());

                case HASH_FNV64:
                    return new HashAlgorithmWrapper(new FNV64());

                case HASH_FNV1A64:
                    return new HashAlgorithmWrapper(new FNV1a64());

                case HASH_JENKINS3:
                    return new HashAlgorithmWrapper(new Jenkins3());

                case HASH_JS:
                    return new HashAlgorithmWrapper(new JS());

                case HASH_MURMUR2:
                    return new HashAlgorithmWrapper(new Murmur2());

                case HASH_MURMUR2_64:
                    return new HashAlgorithmWrapper(new Murmur2_64());

                case HASH_MURMUR3:
                    return new HashAlgorithmWrapper(new Murmur3());

                case HASH_MURMUR3_128:
                    return new HashAlgorithmWrapper(new Murmur3_128());

                case HASH_ONEATTIME:
                    return new HashAlgorithmWrapper(new OneAtTime());

                case HASH_PJW:
                    return new HashAlgorithmWrapper(new PJW());

                case HASH_ROTATING:
                    return new HashAlgorithmWrapper(new Rotating());

                case HASH_RS:
                    return new HashAlgorithmWrapper(new RS());

                case HASH_SDBM:
                    return new HashAlgorithmWrapper(new SDBM());

                case HASH_SHIFTANDXOR:
                    return new HashAlgorithmWrapper(new ShiftAndXor());

                case HASH_SUPERFAST:
                    return new HashAlgorithmWrapper(new SuperFast());

                case HASH_SIPHASH:
                    return new HashAlgorithmWrapper(new HashLib.Hash64.SipHash());

                default:
                    throw new Exception(MSG_INVALID_HASH);
            }
        }

        //--------------------------------------------------------------------------------

        private static void KeyGen
        (
              short keysize
            , short blocksize
            , bool  hightdiv = false
        ){
            Program.AssertSymmetricSizes(ref keysize, ref blocksize, hightdiv);

            byte[]      bs = null;
            byte[]      bp = Program.GetBytes(_password);
            bool        bi = !string.IsNullOrEmpty(_iv);
            DeriveBytes db;

            hightdiv = _codechanged;

            if (bi)
            {
                if (blocksize < 4)
                {
                    _iv = string.Empty;
                    Messenger.Print(Messenger.Icon.WARNING, MSG_IV_DOES_NOT_ALLOW, false, true);
                }

                else if ((_sk.iv = Program.GetBytes(_iv)).Length != blocksize)
                    throw new Exception(string.Format(MSG_INVALID_IV, blocksize));

                if (hightdiv != _codechanged)
                {
                    Array.Clear(bp, 0, bp.Length);
                    bp = Program.GetBytes(_password);
                }
            }

            else if (blocksize < 4)
                bi = true;

            if (string.IsNullOrEmpty(_salt))
            {
                using (HashAlgorithm ha = Program.GetHashAlgorithm())
                {
                    ha.Initialize();
                    bs = ha.ComputeHash(bp);

                    for (int i = _iterations; --i > 0; )
                        bs = ha.ComputeHash(bs);
                }
            }

            else if ((bs = _encoding.GetBytes(_salt)).Length < 8)
                throw new Exception("The salt must be at least 8 characters long!");

            switch (_hash)
            {
                case HASH_BLAKE224:
                    db = new PBKDF2<HMACGEN<Blake224>>(bp, bs, _iterations);
                    break;

                case HASH_BLAKE256:
                    db = new PBKDF2<HMACGEN<Blake256>>(bp, bs, _iterations);
                    break;

                case HASH_BLAKE384:
                    db = new PBKDF2<HMACGEN<Blake384>>(bp, bs, _iterations);
                    break;

                case HASH_BLAKE512:
                    db = new PBKDF2<HMACGEN<Blake512>>(bp, bs, _iterations);
                    break;

                case HASH_BMW224:
                    db = new PBKDF2<HMACGEN<BlueMidnightWish224>>(bp, bs, _iterations);
                    break;

                case HASH_BMW256:
                    db = new PBKDF2<HMACGEN<BlueMidnightWish256>>(bp, bs, _iterations);
                    break;

                case HASH_BMW384:
                    db = new PBKDF2<HMACGEN<BlueMidnightWish384>>(bp, bs, _iterations);
                    break;

                case HASH_BMW512:
                    db = new PBKDF2<HMACGEN<BlueMidnightWish512>>(bp, bs, _iterations);
                    break;

                case HASH_CUBE224:
                    db = new PBKDF2<HMACGEN<CubeHash224>>(bp, bs, _iterations);
                    break;

                case HASH_CUBE256:
                    db = new PBKDF2<HMACGEN<CubeHash256>>(bp, bs, _iterations);
                    break;

                case HASH_CUBE384:
                    db = new PBKDF2<HMACGEN<CubeHash384>>(bp, bs, _iterations);
                    break;

                case HASH_CUBE512:
                    db = new PBKDF2<HMACGEN<CubeHash512>>(bp, bs, _iterations);
                    break;

                case HASH_ECHO224:
                    db = new PBKDF2<HMACGEN<Echo224>>(bp, bs, _iterations);
                    break;

                case HASH_ECHO256:
                    db = new PBKDF2<HMACGEN<Echo256>>(bp, bs, _iterations);
                    break;

                case HASH_ECHO384:
                    db = new PBKDF2<HMACGEN<Echo384>>(bp, bs, _iterations);
                    break;

                case HASH_ECHO512:
                    db = new PBKDF2<HMACGEN<Echo512>>(bp, bs, _iterations);
                    break;

                case HASH_FUGUE224:
                    db = new PBKDF2<HMACGEN<Fugue224>>(bp, bs, _iterations);
                    break;

                case HASH_FUGUE256:
                    db = new PBKDF2<HMACGEN<Fugue256>>(bp, bs, _iterations);
                    break;

                case HASH_FUGUE384:
                    db = new PBKDF2<HMACGEN<Fugue384>>(bp, bs, _iterations);
                    break;

                case HASH_FUGUE512:
                    db = new PBKDF2<HMACGEN<Fugue512>>(bp, bs, _iterations);
                    break;

                case HASH_GROESTL224:
                    db = new PBKDF2<HMACGEN<Groestl224>>(bp, bs, _iterations);
                    break;

                case HASH_GROESTL256:
                    db = new PBKDF2<HMACGEN<Groestl256>>(bp, bs, _iterations);
                    break;

                case HASH_GROESTL384:
                    db = new PBKDF2<HMACGEN<Groestl384>>(bp, bs, _iterations);
                    break;

                case HASH_GROESTL512:
                    db = new PBKDF2<HMACGEN<Groestl512>>(bp, bs, _iterations);
                    break;

                case HASH_HAMSI224:
                    db = new PBKDF2<HMACGEN<Hamsi224>>(bp, bs, _iterations);
                    break;

                case HASH_HAMSI256:
                    db = new PBKDF2<HMACGEN<Hamsi256>>(bp, bs, _iterations);
                    break;

                case HASH_HAMSI384:
                    db = new PBKDF2<HMACGEN<Hamsi384>>(bp, bs, _iterations);
                    break;

                case HASH_HAMSI512:
                    db = new PBKDF2<HMACGEN<Hamsi512>>(bp, bs, _iterations);
                    break;

                case HASH_JH224:
                    db = new PBKDF2<HMACGEN<JH224>>(bp, bs, _iterations);
                    break;

                case HASH_JH256:
                    db = new PBKDF2<HMACGEN<JH256>>(bp, bs, _iterations);
                    break;

                case HASH_JH384:
                    db = new PBKDF2<HMACGEN<JH384>>(bp, bs, _iterations);
                    break;

                case HASH_JH512:
                    db = new PBKDF2<HMACGEN<JH512>>(bp, bs, _iterations);
                    break;

                case HASH_KECCAK224:
                    db = new PBKDF2<HMACGEN<Keccak224>>(bp, bs, _iterations);
                    break;

                case HASH_KECCAK256:
                    db = new PBKDF2<HMACGEN<Keccak256>>(bp, bs, _iterations);
                    break;

                case HASH_KECCAK384:
                    db = new PBKDF2<HMACGEN<Keccak384>>(bp, bs, _iterations);
                    break;

                case HASH_KECCAK512:
                    db = new PBKDF2<HMACGEN<Keccak512>>(bp, bs, _iterations);
                    break;

                case HASH_LUFFA224:
                    db = new PBKDF2<HMACGEN<Luffa224>>(bp, bs, _iterations);
                    break;
                
                case HASH_LUFFA256:
                    db = new PBKDF2<HMACGEN<Luffa256>>(bp, bs, _iterations);
                    break;

                case HASH_LUFFA384:
                    db = new PBKDF2<HMACGEN<Luffa384>>(bp, bs, _iterations);
                    break;

                case HASH_LUFFA512:
                    db = new PBKDF2<HMACGEN<Luffa512>>(bp, bs, _iterations);
                    break;

                case HASH_SHABAL224:
                    db = new PBKDF2<HMACGEN<Shabal224>>(bp, bs, _iterations);
                    break;

                case HASH_SHABAL256:
                    db = new PBKDF2<HMACGEN<Shabal256>>(bp, bs, _iterations);
                    break;

                case HASH_SHABAL384:
                    db = new PBKDF2<HMACGEN<Shabal384>>(bp, bs, _iterations);
                    break;

                case HASH_SHABAL512:
                    db = new PBKDF2<HMACGEN<Shabal512>>(bp, bs, _iterations);
                    break;

                case HASH_SHAVITE_224:
                    db = new PBKDF2<HMACGEN<SHAvite3_224>>(bp, bs, _iterations);
                    break;

                case HASH_SHAVITE_256:
                    db = new PBKDF2<HMACGEN<SHAvite3_256>>(bp, bs, _iterations);
                    break;

                case HASH_SHAVITE_384:
                    db = new PBKDF2<HMACGEN<SHAvite3_384>>(bp, bs, _iterations);
                    break;

                case HASH_SHAVITE_512:
                    db = new PBKDF2<HMACGEN<SHAvite3_512>>(bp, bs, _iterations);
                    break;

                case HASH_SIMD224:
                    db = new PBKDF2<HMACGEN<SIMD224>>(bp, bs, _iterations);
                    break;

                case HASH_SIMD256:
                    db = new PBKDF2<HMACGEN<SIMD256>>(bp, bs, _iterations);
                    break;

                case HASH_SIMD384:
                    db = new PBKDF2<HMACGEN<SIMD384>>(bp, bs, _iterations);
                    break;

                case HASH_SIMD512:
                    db = new PBKDF2<HMACGEN<SIMD512>>(bp, bs, _iterations);
                    break;

                case HASH_SKEIN224:
                    db = new PBKDF2<HMACGEN<Skein224>>(bp, bs, _iterations);
                    break;

                case HASH_SKEIN256:
                    db = new PBKDF2<HMACGEN<Skein256>>(bp, bs, _iterations);
                    break;

                case HASH_SKEIN384:
                    db = new PBKDF2<HMACGEN<Skein384>>(bp, bs, _iterations);
                    break;

                case HASH_SKEIN512:
                    db = new PBKDF2<HMACGEN<Skein512>>(bp, bs, _iterations);
                    break;

                case HASH_RIPEMD:
                    db = new PBKDF2<HMACGEN<RIPEMD>>(bp, bs, _iterations);
                    break;

                case HASH_RIPEMD128:
                    db = new PBKDF2<HMACGEN<RIPEMD128>>(bp, bs, _iterations);
                    break;

                case HASH_RIPEMD160:
                    db = new PBKDF2<HMACRIPEMD160>(bp, bs, _iterations);
                    break;

                case HASH_RIPEMD256:
                    db = new PBKDF2<HMACGEN<RIPEMD256>>(bp, bs, _iterations);
                    break;

                case HASH_RIPEMD320:
                    db = new PBKDF2<HMACGEN<RIPEMD320>>(bp, bs, _iterations);
                    break;

                case HASH_SHA512:
                    db = new PBKDF2<HMACSHA512>(bp, bs, _iterations);
                    break;

                case HASH_SHA384:
                    db = new PBKDF2<HMACSHA384>(bp, bs, _iterations);
                    break;

                case HASH_SHA256:
                    db = new PBKDF2<HMACSHA256>(bp, bs, _iterations);
                    break;

                case HASH_SHA224:
                    db = new PBKDF2<HMACGEN<SHA224>>(bp, bs, _iterations);
                    break;

                case HASH_SHA1:
                    db = new Rfc2898DeriveBytes(bp, bs, _iterations);
                    break;

                case HASH_SHA0:
                    db = new PBKDF2<HMACGEN<SHA0>>(bp, bs, _iterations);
                    break;

                case HASH_MD5:
                    db = new PasswordDeriveBytes(bp, bs, _hash, _iterations);
                    break;

                case HASH_MD4:
                    db = new PBKDF2<HMACGEN<MD4>>(bp, bs, _iterations);
                    break;

                case HASH_MD2:
                    db = new PBKDF2<HMACGEN<MD2>>(bp, bs, _iterations);
                    break;

                case GOST:
                    db = new PBKDF2<HMACGEN<Gost>>(bp, bs, _iterations);
                    break;

                case HASH_GRINDAHL256:
                    db = new PBKDF2<HMACGEN<Grindahl256>>(bp, bs, _iterations);
                    break;

                case HASH_GRINDAHL512:
                    db = new PBKDF2<HMACGEN<Grindahl512>>(bp, bs, _iterations);
                    break;

                case HASH_HAS160:
                    db = new PBKDF2<HMACGEN<HAS160>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL3_128:
                    db = new PBKDF2<HMACGEN<Haval_3_128>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL3_160:
                    db = new PBKDF2<HMACGEN<Haval_3_160>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL3_192:
                    db = new PBKDF2<HMACGEN<Haval_3_192>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL3_224:
                    db = new PBKDF2<HMACGEN<Haval_3_224>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL3_256:
                    db = new PBKDF2<HMACGEN<Haval_3_256>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL4_128:
                    db = new PBKDF2<HMACGEN<Haval_4_128>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL4_160:
                    db = new PBKDF2<HMACGEN<Haval_4_160>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL4_192:
                    db = new PBKDF2<HMACGEN<Haval_4_192>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL4_224:
                    db = new PBKDF2<HMACGEN<Haval_4_224>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL4_256:
                    db = new PBKDF2<HMACGEN<Haval_4_256>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL5_128:
                    db = new PBKDF2<HMACGEN<Haval_5_128>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL5_160:
                    db = new PBKDF2<HMACGEN<Haval_5_160>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL5_192:
                    db = new PBKDF2<HMACGEN<Haval_5_192>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL5_224:
                    db = new PBKDF2<HMACGEN<Haval_5_224>>(bp, bs, _iterations);
                    break;

                case HASH_HAVAL5_256:
                    db = new PBKDF2<HMACGEN<Haval_5_256>>(bp, bs, _iterations);
                    break;

                case HASH_PANAMA:
                    db = new PBKDF2<HMACGEN<Panama>>(bp, bs, _iterations);
                    break;

                case HASH_RG32:
                    db = new PBKDF2<HMACGEN<RadioGatun32>>(bp, bs, _iterations);
                    break;

                case HASH_RG64:
                    db = new PBKDF2<HMACGEN<RadioGatun64>>(bp, bs, _iterations);
                    break;

                case HASH_SNEFRU4_128:
                    db = new PBKDF2<HMACGEN<Snefru_4_128>>(bp, bs, _iterations);
                    break;

                case HASH_SNEFRU4_256:
                    db = new PBKDF2<HMACGEN<Snefru_4_256>>(bp, bs, _iterations);
                    break;

                case HASH_SNEFRU8_128:
                    db = new PBKDF2<HMACGEN<Snefru_8_128>>(bp, bs, _iterations);
                    break;

                case HASH_SNEFRU8_256:
                    db = new PBKDF2<HMACGEN<Snefru_8_256>>(bp, bs, _iterations);
                    break;

                case HASH_TIGER2:
                    db = new PBKDF2<HMACGEN<Tiger2>>(bp, bs, _iterations);
                    break;

                case HASH_TIGER3_192:
                    db = new PBKDF2<HMACGEN<Tiger_3_192>>(bp, bs, _iterations);
                    break;

                case HASH_TIGER4_192:
                    db = new PBKDF2<HMACGEN<Tiger_4_192>>(bp, bs, _iterations);
                    break;

                case HASH_WHIRLPOOL:
                    db = new PBKDF2<HMACGEN<Whirlpool>>(bp, bs, _iterations);
                    break;

                case HASH_AP:
                    db = new PBKDF2<HMACGEN<AP>>(bp, bs, _iterations);
                    break;

                case HASH_BERNSTEIN:
                    db = new PBKDF2<HMACGEN<Bernstein>>(bp, bs, _iterations);
                    break;

                case HASH_BERNSTEIN1:
                    db = new PBKDF2<HMACGEN<Bernstein1>>(bp, bs, _iterations);
                    break;

                case HASH_BKDR:
                    db = new PBKDF2<HMACGEN<BKDR>>(bp, bs, _iterations);
                    break;

                case HASH_DEK:
                    db = new PBKDF2<HMACGEN<DEK>>(bp, bs, _iterations);
                    break;

                case HASH_DJB:
                    db = new PBKDF2<HMACGEN<DJB>>(bp, bs, _iterations);
                    break;

                case HASH_DOTNET:
                    db = new PBKDF2<HMACGEN<DotNet>>(bp, bs, _iterations);
                    break;

                case HASH_ELF:
                    db = new PBKDF2<HMACGEN<ELF>>(bp, bs, _iterations);
                    break;

                case HASH_FNV:
                    db = new PBKDF2<HMACGEN<FNV>>(bp, bs, _iterations);
                    break;

                case HASH_FNV1A:
                    db = new PBKDF2<HMACGEN<FNV1a>>(bp, bs, _iterations);
                    break;

                case HASH_FNV64:
                    db = new PBKDF2<HMACGEN<FNV64>>(bp, bs, _iterations);
                    break;

                case HASH_FNV1A64:
                    db = new PBKDF2<HMACGEN<FNV1a64>>(bp, bs, _iterations);
                    break;

                case HASH_JENKINS3:
                    db = new PBKDF2<HMACGEN<Jenkins3>>(bp, bs, _iterations);
                    break;

                case HASH_JS:
                    db = new PBKDF2<HMACGEN<JS>>(bp, bs, _iterations);
                    break;

                case HASH_MURMUR2:
                    db = new PBKDF2<HMACGEN<Murmur2>>(bp, bs, _iterations);
                    break;

                case HASH_MURMUR2_64:
                    db = new PBKDF2<HMACGEN<Murmur2_64>>(bp, bs, _iterations);
                    break;

                case HASH_MURMUR3:
                    db = new PBKDF2<HMACGEN<Murmur3>>(bp, bs, _iterations);
                    break;

                case HASH_ONEATTIME:
                    db = new PBKDF2<HMACGEN<OneAtTime>>(bp, bs, _iterations);
                    break;

                case HASH_PJW:
                    db = new PBKDF2<HMACGEN<PJW>>(bp, bs, _iterations);
                    break;

                case HASH_ROTATING:
                    db = new PBKDF2<HMACGEN<Rotating>>(bp, bs, _iterations);
                    break;

                case HASH_RS:
                    db = new PBKDF2<HMACGEN<RS>>(bp, bs, _iterations);
                    break;

                case HASH_SDBM:
                    db = new PBKDF2<HMACGEN<SDBM>>(bp, bs, _iterations);
                    break;

                case HASH_SHIFTANDXOR:
                    db = new PBKDF2<HMACGEN<ShiftAndXor>>(bp, bs, _iterations);
                    break;

                case HASH_SUPERFAST:
                    db = new PBKDF2<HMACGEN<SuperFast>>(bp, bs, _iterations);
                    break;

                case HASH_SIPHASH:
                    db = new PBKDF2<HMACGEN<HashLib.Hash64.SipHash>>(bp, bs, _iterations);
                    break;

                case HASH_MURMUR3_128:
                    db = new PBKDF2<HMACGEN<Murmur3_128>>(bp, bs, _iterations);
                    break;

                default:
                    throw new Exception(MSG_INVALID_HASH);
            }

            _sk.key = db.GetBytes(keysize);

            if (!bi)
                _sk.iv = db.GetBytes(blocksize);

            db.Reset();
            Array.Clear(bp, 0, bp.Length);
            Array.Clear(bs, 0, bs.Length);
        }

        //----------------------------------------------------------------------------------

        private static object GetKeyExchangeProvider 
        (
              RSACryptoServiceProvider rsa
            , string                   path
            , bool                     publickey
        ){

            string    emsg  = publickey ? MSG_INVALID_PUBLIC_KEY : MSG_INVALID_PRIVATE_KEY;
            Exception inner = new Exception(MSG_INNER_EXCEPTION_CTRL);

            if (!File.Exists(path))
                throw new Exception(emsg);

            byte[] data = File.ReadAllBytes(path);

            try
            {
                AsymmetricKeyParameter akp = Program.ImportAsymmetricKey
                (
                      data
                    , publickey
                    , emsg
                );

                if (akp is ElGamalKeyParameters)
                {
                    if (!akp.IsPrivate && !publickey)
                        throw new Exception(emsg, inner);

                    Array.Clear(data, 0, data.Length);
                    return akp;
                }

                else if (akp is RsaKeyParameters)
                {
                    if (akp.IsPrivate)
                        Program.SetRsaFromPrivateKeyParameters(rsa, (RsaPrivateCrtKeyParameters)akp);

                    else
                    {
                        if (!publickey)
                            throw new Exception(emsg, inner);

                        Program.SetRsaFromPublicKeyParameters(rsa, (RsaKeyParameters)akp);
                    }

                    Array.Clear(data, 0, data.Length);
                    return rsa;
                }
            }

            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException.Message == MSG_INNER_EXCEPTION_CTRL)
                    throw e;
            }

            try
            {
                NaccacheSternKeyParameters k = Program.NaccacheSternImportKey(data, publickey, emsg);

                Array.Clear(data, 0, data.Length);
                return k;
            }

            catch (Exception) {}

            Program.RsaImportKey(rsa, data, publickey, emsg);
            Array.Clear(data, 0, data.Length);

            return rsa;
        }

        //----------------------------------------------------------------------------------

        private static byte[] KeyExchange (object provider, byte[] data)
        {
            if (provider is RSACryptoServiceProvider)
                return Program.CryptoRsa((RSACryptoServiceProvider)provider, data);

            else if (provider is ElGamalKeyParameters)
                return Program.CryptoElGamal((ElGamalKeyParameters)provider, data);

            else if (provider is NaccacheSternKeyParameters)
                return Program.CryptoNaccacheStern((NaccacheSternKeyParameters)provider, data);

            throw new Exception(MSG_UNSUPPORTED_KEY_PROVIDER);
        }

        //----------------------------------------------------------------------------------

        private static bool IsPrivateKey (object provider)
        {
            if (provider is RSACryptoServiceProvider)
                return !((RSACryptoServiceProvider)provider).PublicOnly;

            else if (provider is ElGamalKeyParameters)
                return ((ElGamalKeyParameters)provider).IsPrivate;

            else if (provider is NaccacheSternKeyParameters)
                return ((NaccacheSternKeyParameters)provider).IsPrivate;

            throw new Exception(MSG_UNSUPPORTED_KEY_PROVIDER);
        }

        //----------------------------------------------------------------------------------

        private static byte[] GetBytes (int n)
        {
            byte [] b = BitConverter.GetBytes(n);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(b);

            return b;
        }

        //----------------------------------------------------------------------------------

        private static int ToInt32 (byte[] b)
        {
            if (BitConverter.IsLittleEndian)
                Array.Reverse(b);

            return BitConverter.ToInt32(b, 0);
        }

        //----------------------------------------------------------------------------------
        
        private static int ResolveKeyExchange 
        (
              object provider
            , Stream stream
            , bool   biv      = false
            , bool   hightdiv = false
        ){ 
            short  k = _keysize;
            short  b = _blocksize;
            int    m = 0; 
            int    n = 0;
            byte[] x, l;
            
            Program.AssertSymmetricSizes(ref k, ref b, hightdiv);

            if (_job == CryptoJob.ENCRYPT)
            {
                x = Program.KeyExchange(provider, _sk.key = Program.GetRandomBytes(k));
                l = Program.GetBytes(x.Length);

                stream.Write(l, 0, l.Length);
                stream.Write(x, 0, x.Length);

                if (biv)
                {
                    Array.Clear(l, 0, l.Length);
                    Array.Clear(x, 0, x.Length);

                    x = Program.KeyExchange(provider, _sk.iv = Program.GetRandomBytes(b));
                    l = Program.GetBytes(x.Length);

                    stream.Write(l, 0, l.Length);
                    stream.Write(x, 0, x.Length);
                }
            }

            else
            {
                string c = "Wrong certificate or private key!";
                string f = "Wrong input file!";
                long   t = stream.Length;

                if (!Program.IsPrivateKey(provider))
                    throw new Exception(MSG_PUBLIC_KEY_ONLY);

                l  = new byte[4];
                if (stream.Read(l, 0, l.Length) < l.Length)
                    throw new Exception(f);

                if ((m = Program.ToInt32(l)) > (t -= l.Length) | m < 0)
                    throw new Exception(f);

                t -= m;
                x  = new byte[m];
                if (stream.Read(x, 0, m) < m)
                    throw new Exception(f);

                try
                {
                    _sk.key = Program.KeyExchange(provider, x);
                }
                
                catch (Exception e)
                {
                    throw new Exception(c, e);
                }

                n = l.Length + x.Length;

                if (biv)
                {
                    Array.Clear(l, 0, l.Length);
                    Array.Clear(x, 0, x.Length);

                    if (stream.Read(l, 0, l.Length) < l.Length)
                        throw new Exception(f);

                    if ((m = Program.ToInt32(l)) > (t -= l.Length) | m < 0)
                        throw new Exception(f);

                    x = new byte[m];
                    if (stream.Read(x, 0, m) < m)
                        throw new Exception(f);

                    try
                    {
                        _sk.iv = Program.KeyExchange(provider, x);
                    }

                    catch (Exception e)
                    {
                        throw new Exception(c, e);
                    }

                    n = l.Length + x.Length;
                }
            }

            Array.Clear(l, 0, l.Length);
            Array.Clear(x, 0, x.Length);

            _keyexchange = true;
            return n;
        }
        
        //----------------------------------------------------------------------------------

        private static string ResolveKeyExchange (ref bool publickey)
        {   
            string b = "public";
            string v = "private";
            string e = "encrypt";
            string d = "decrypt";
            string q = "A {0} key was specified to {1} when needed is a {2} key." +
                       "\n\n> Do you want to exchange them?";

            if (!string.IsNullOrEmpty(_private_key))
            {
                if (_job == CryptoJob.DECRYPT)
                {
                    if (!File.Exists(_private_key))
                        throw new Exception(MSG_INVALID_PRIVATE_KEY);

                    publickey = false;
                    return _private_key;
                }

                else if (string.IsNullOrEmpty(_public_key)) 
                {
                    if (!Program.Question(string.Format(q, v, e, b)))
                        throw new Exception(MSG_INVALID_PUBLIC_KEY);

                    else
                    {
                        _public_key  = _private_key;
                        _private_key = string.Empty;

                        return Program.ResolveKeyExchange(ref publickey);
                    }
                }
            }

            if (!string.IsNullOrEmpty(_public_key))
            {
                if (_job == CryptoJob.ENCRYPT)
                {
                    if (!File.Exists(_public_key))
                        throw new Exception(MSG_INVALID_PUBLIC_KEY);

                    publickey = true;
                    return _public_key;
                }

                else if (string.IsNullOrEmpty(_private_key))
                {
                    if (!Program.Question(string.Format(q, b, d, v)))
                        throw new Exception(MSG_INVALID_PRIVATE_KEY);

                    else
                    {
                        _private_key = _public_key;
                        _public_key  = string.Empty;

                        return Program.ResolveKeyExchange(ref publickey);
                    }
                }
            }

            return null;
        }

        //----------------------------------------------------------------------------------

        private static bool ResolveEcdhKeyExchange (bool hightdiv = false)
        {
            AsymmetricKeyParameter pbk = null;
            AsymmetricKeyParameter pvk = null;

            if (!string.IsNullOrEmpty(_public_key))
            {
                try
                {
                    pbk = Program.ImportAsymmetricKey
                    (
                          _public_key
                        , true
                        , MSG_INVALID_PUBLIC_KEY
                    );
                }

                catch (Exception e)
                {
                    if (e.InnerException != null && e.InnerException.Message == MSG_INNER_EXCEPTION_CTRL)
                        throw e;
                }
            }

            if (!string.IsNullOrEmpty(_private_key))
            {
                try
                {
                    pvk = Program.ImportAsymmetricKey
                    (
                          _private_key
                        , false
                        , MSG_INVALID_PRIVATE_KEY
                    );
                }

                catch (Exception e)
                {
                    if (e.InnerException != null && e.InnerException.Message == MSG_INNER_EXCEPTION_CTRL)
                        throw e;
                }
            }

            if (pbk == null || !(pbk is ECPublicKeyParameters))
            {
                if (pvk != null && pvk is ECPrivateKeyParameters)
                    throw new Exception(MSG_INVALID_PUBLIC_KEY);

                return false;
            }

            if (pvk == null || !(pvk is ECPrivateKeyParameters))
            {
                if (pbk != null && pbk is ECPublicKeyParameters)
                    throw new Exception(MSG_INVALID_PRIVATE_KEY);

                return false;
            }
            
            ECDHCBasicAgreement eca = new ECDHCBasicAgreement();
            byte[]              tmp;

            eca.Init(pvk);
            tmp = eca.CalculateAgreement(pbk).ToByteArray();

            ECDHKekGenerator eck = new ECDHKekGenerator(Program.GetBouncyCastleDigest());
            eck.Init(new DHKdfParameters(NistObjectIdentifiers.Aes, tmp.Length, tmp));

            short k = _keysize;
            short b = _blocksize;

            Program.AssertSymmetricSizes(ref k, ref b, hightdiv);

            tmp = new byte[k];
            eck.GenerateBytes(tmp, 0, tmp.Length);
            _sk.key = tmp;

            if (b >= 4)
            {
                tmp = new byte[b];
                eck.GenerateBytes(tmp, 0, tmp.Length);
                _sk.iv = tmp;
            }

            return _keyexchange = true;
        }

        //----------------------------------------------------------------------------------

        private static void SetSymmetricKey
        (
              short keysize
            , short blocksize
            , bool  hightdiv
        ){
            Program.AssertSymmetricSizes(ref keysize, ref blocksize, hightdiv);

            if ((_sk.key = Program.GetBytes(_key)).Length != keysize)
                throw new Exception(string.Format(MSG_INVALID_KEY, keysize));

            if (blocksize > 0)
            {
                hightdiv = _codechanged;

                if (string.IsNullOrEmpty(_iv) || (_sk.iv = Program.GetBytes(_iv)).Length != blocksize)
                    throw new Exception(string.Format(MSG_INVALID_IV, blocksize));

                if (hightdiv != _codechanged)
                {
                    Array.Clear(_sk.key, 0, _sk.key.Length);

                    if ((_sk.key = Program.GetBytes(_key)).Length != keysize)
                        throw new Exception(string.Format(MSG_INVALID_KEY, keysize));
                }
            }

            else if (!string.IsNullOrEmpty(_iv))
            {
                _iv = string.Empty;
                Messenger.Print(Messenger.Icon.WARNING, MSG_IV_DOES_NOT_ALLOW, false, true);
            }
        }

        //----------------------------------------------------------------------------------

        private static IBlockCipherPadding GetBouncyCastlePadding ()
        {
            switch (_padding)
            {
                case CryptoPadding.PKCS7:
                    return new Pkcs7Padding();

                case CryptoPadding.X923:
                    return new X923Padding();

                case CryptoPadding.ISO10126:
                    return new ISO10126d2Padding();

                case CryptoPadding.ISO7816D4:
                    return new ISO7816d4Padding();
                
                case CryptoPadding.TBC:
                    return new TbcPadding();

                default:
                    throw new Exception(MSG_INVALID_PADDING_MODE);
            }
        }

        //----------------------------------------------------------------------------------

        private static void ValidateIntrinsicPadding ()
        {
            switch (_padding)
            {
                case CryptoPadding.PKCS7:
                case CryptoPadding.X923:
                case CryptoPadding.ISO10126:
                case CryptoPadding.Zeros:
                    break;

                default:
                    throw new Exception(MSG_INVALID_PADDING_MODE);
            }
        }

        //----------------------------------------------------------------------------------

        private static IBlockCipher GetBlockCipherMode (IBlockCipher engine)
        {
            switch (_ciphermode)
            {
                case CipherMode.CBC:
                    return new CbcBlockCipher(engine);

                case CipherMode.CFB:
                    return new CfbBlockCipher(engine, engine.GetBlockSize() * 8);

                case CipherMode.OFB:
                    return new OfbBlockCipher(engine, engine.GetBlockSize() * 8);

                default:
                    throw new Exception(MSG_INVALID_CIPHER_MODE);
            }
        }

        //----------------------------------------------------------------------------------

        private static void Write (Stream src, Stream dest, long srclen)
        {
            byte[] b = new byte[_buffersize];
            long   n = 0;

            for (int c; (c = src.Read(b, 0, _buffersize)) > 0; )
            {
                dest.Write(b, 0, c);
                Program.Progress(n += c, srclen, c);
            }

            Array.Clear(b, 0, b.Length);

            if (_percent < 100)
                Program.Progress(srclen, srclen, 0);
        }

        //----------------------------------------------------------------------------------

        private static void Crypto (SymmetricAlgorithm sa, Stream src, Stream dest, int offset)
        {
            if (_job == CryptoJob.ENCRYPT)
            {
                using (ICryptoTransform ct = sa.CreateEncryptor(_sk.key, _sk.iv))
                {
                    using (CryptoStream cs = new CryptoStream(dest, ct, CryptoStreamMode.Write))
                    {
                        Program.Write(src, cs, src.Length);
                        cs.FlushFinalBlock();
                    }
                }
            }

            else using (ICryptoTransform ct = sa.CreateDecryptor(_sk.key, _sk.iv))
                using (CryptoStream cs = new CryptoStream(src, ct, CryptoStreamMode.Read))
                    Program.Write(cs, dest, src.Length - offset);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoRc2 (Stream src, Stream dest, object provider = null)
        {
            int n = 0;

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , !_without_iv
            );

            if (_without_iv)
            {
                BufferedBlockCipher bc = new PaddedBufferedBlockCipher
                (
                      Program.GetBlockCipherMode(new RC2Engine())
                    , Program.GetBouncyCastlePadding()
                );

                bc.Init(_job == CryptoJob.ENCRYPT, new KeyParameter(_sk.key));
                Program.Write(bc, src, dest, n);
            }

            else using (RC2CryptoServiceProvider sp = new RC2CryptoServiceProvider())
            {
                sp.Mode      = _ciphermode;
                sp.Padding   = (PaddingMode)_padding;
                sp.KeySize   = _keysize;
                sp.BlockSize = _blocksize;
                
                Program.Crypto(sp, src, dest, n);
            }
        }

        //----------------------------------------------------------------------------------

        private static void CryptoDes (Stream src, Stream dest, object provider = null)
        {
            int n = 0;

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , !_without_iv
            );

            if (_without_iv)
            {
                BufferedBlockCipher bc = new PaddedBufferedBlockCipher
                (
                      Program.GetBlockCipherMode(new DesEngine())
                    , Program.GetBouncyCastlePadding()
                );


                bc.Init(_job == CryptoJob.ENCRYPT, new KeyParameter(_sk.key));
                Program.Write(bc, src, dest, n);
            }

            else using (DESCryptoServiceProvider sp = new DESCryptoServiceProvider())
            {
                sp.Mode      = _ciphermode;
                sp.Padding   = (PaddingMode)_padding;
                sp.KeySize   = _keysize;
                sp.BlockSize = _blocksize;

                Program.Crypto(sp, src, dest, n);
            }
        }

        //----------------------------------------------------------------------------------

        private static void CryptoTripleDes (Stream src, Stream dest, object provider = null)
        {
            int n = 0;

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , !_without_iv
            );

            if (_without_iv)
            {
                BufferedBlockCipher bc = new PaddedBufferedBlockCipher
                (
                      Program.GetBlockCipherMode(new DesEdeEngine())
                    , Program.GetBouncyCastlePadding()
                );

                bc.Init(_job == CryptoJob.ENCRYPT, new KeyParameter(_sk.key));
                Program.Write(bc, src, dest, n);
            }

            else using (TripleDESCryptoServiceProvider sp = new TripleDESCryptoServiceProvider())
            {
                sp.Mode      = _ciphermode;
                sp.Padding   = (PaddingMode)_padding;
                sp.KeySize   = _keysize;
                sp.BlockSize = _blocksize;

                Program.Crypto(sp, src, dest, n);
            }
        }

        //----------------------------------------------------------------------------------

        private static void CryptoRijndael (Stream src, Stream dest, object provider = null)
        {
            int n = 0;

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , !_without_iv
            );

            if (_without_iv)
            {
                BufferedBlockCipher bc = new PaddedBufferedBlockCipher
                (
                      Program.GetBlockCipherMode(new RijndaelEngine(_blocksize))
                    , Program.GetBouncyCastlePadding()
                );

                bc.Init(_job == CryptoJob.ENCRYPT, new KeyParameter(_sk.key));
                Program.Write(bc, src, dest, n);
            }

            else using (RijndaelManaged rm = new RijndaelManaged())
            {
                rm.Mode         = _ciphermode;
                rm.Padding      = (PaddingMode)_padding;
                rm.KeySize      = _keysize;
                rm.BlockSize    = _blocksize;
                rm.FeedbackSize = _feedbacksize;

                Program.Crypto(rm, src, dest, n);
            }
        }

        //----------------------------------------------------------------------------------

        private static void CryptoAes (Stream src, Stream dest, object provider = null)
        {
            if (!_without_iv)
                Program.CryptoRijndael(src, dest, provider);

            else
            {
                int                 n  = 0;
                BufferedBlockCipher bc = new PaddedBufferedBlockCipher
                (
                      Program.GetBlockCipherMode(new AesEngine())
                    , Program.GetBouncyCastlePadding()
                );

                if (provider != null) n = Program.ResolveKeyExchange
                (
                      provider
                    , _job == CryptoJob.ENCRYPT ? dest : src
                );

                bc.Init(_job == CryptoJob.ENCRYPT, new KeyParameter(_sk.key));
                Program.Write(bc, src, dest, n);
            }
        }

        //----------------------------------------------------------------------------------

        private static void CryptoMars (Stream src, Stream dest, object provider = null)
        {
            int n = 0;

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , true
            );

            using (MarsManaged mm = new MarsManaged())
            {
                mm.KeySize   = _keysize;
                mm.BlockSize = _blocksize;
                mm.Mode      = _ciphermode;
                mm.Padding   = (PaddingMode)_padding;

                Program.Crypto(mm, src, dest, n);
            }
        }

        //----------------------------------------------------------------------------------

        private static IDigest GetBouncyCastleDigest (int keybits)
        {
            switch (_hash)
            {
                case HASH_RIPEMD256:
                    if (keybits < 1240) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_RIPEMD256
                            , 1240
                        )
                    );

                    return new RipeMD160Digest();

                case HASH_RIPEMD160:
                    if (keybits < 1144) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_RIPEMD160
                            , 1144
                        )
                    );

                    return new RipeMD160Digest();

                case HASH_RIPEMD128:
                    if (keybits < 1112) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_RIPEMD128
                            , 1112
                        )
                    );

                    return new RipeMD128Digest();

                case HASH_SHA512:
                    if (keybits < 1048) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_SHA512
                            , 1048
                        )
                    );

                    return new Sha512Digest();

                case HASH_SHA384:
                    if (keybits < 792) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_SHA384
                            , 792
                        )
                    );

                    return new Sha384Digest();

                case HASH_SHA256:
                    if (keybits < 536) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_SHA256
                            , 536
                        )
                    );

                    return new Sha256Digest();

                case HASH_SHA224:
                    if (keybits < 472) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_SHA224
                            , 472
                        )
                    );

                    return new Sha224Digest();

                case HASH_SHA1:
                    if (keybits < 344) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_SHA1
                            , 344
                        )
                    );

                    return new Sha1Digest();

                case HASH_MD5:
                    if (keybits < 280) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_MD5
                            , 280
                        )
                    );

                    return new MD5Digest();

                case HASH_MD4:
                    if (keybits < 280) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_MD4
                            , 280
                        )
                    );

                    return new MD4Digest();

                case HASH_MD2:
                    if (keybits < 280) throw new Exception
                    (
                        string.Format
                        (
                              MSG_INVALID_HASH_KEY_SIZE
                            , HASH_MD2
                            , 280
                        )
                    );

                    return new MD2Digest();

                default:
                    throw new Exception(MSG_INVALID_HASH);
            }
        }

        //----------------------------------------------------------------------------------

        private static OaepEncoding GetOaepEncoding 
        (
              IAsymmetricBlockCipher engine
            , int                    bits
        ){
            switch (_hash)
            {
                case HASH_SHA512:
                case HASH_SHA384:
                case HASH_SHA256:
                case HASH_SHA224:
                case HASH_SHA1:
                case HASH_MD5:
                    return new OaepEncoding(engine, Program.GetBouncyCastleDigest(bits));        

                default:
                    throw new Exception(MSG_INVALID_HASH);
            }
        }

        //----------------------------------------------------------------------------------

        private static ISigner GetRsaSigner (int bits)
        {
            IDigest h = Program.GetBouncyCastleDigest(bits);

            switch (_rsa_sign)
            {
                case ISO9796D2:
                    return new Iso9796d2PssSigner(new RsaEngine(), h, h.GetDigestSize(), true);

                case PSS:
                    return new PssSigner(new RsaBlindedEngine(), h);

                case RSA:
                    return new RsaDigestSigner(h);

                default:
                    throw new Exception("Invalid Rsa signer!");
            }
        }

        //----------------------------------------------------------------------------------

        private static void CryptoRsa
        (
              RSACryptoServiceProvider rsa
            , Stream                   src
            , Stream                   dest
            , bool                     sign        = false
            , bool                     cleanse     = false
            , bool                     progressbar = true
        ){
            ISigner signer = null;

            if (sign)
            {
                signer = Program.GetRsaSigner(rsa.KeySize);

                if (_job == CryptoJob.ENCRYPT)
                    signer.Init(true, Program.GetRsaPrivateKeyParameters(rsa));

                else signer.Init(false, Program.GetRsaPublicKeyParameters(rsa));
            }

            if (_rsa_bc)
            {
                RsaKeyParameters k = _job == CryptoJob.ENCRYPT ? Program.GetRsaPublicKeyParameters(rsa) :
                                     Program.GetRsaPrivateKeyParameters(rsa);

                IAsymmetricBlockCipher abc;

                if (_padding == CryptoPadding.OAEP)
                    abc = Program.GetOaepEncoding(new RsaEngine(), k.Modulus.BitLength);

                else if (_padding == CryptoPadding.ISO9796D1)
                    abc = new ISO9796d1Encoding(new RsaEngine());

                else if (_padding == CryptoPadding.PKCS1)
                    abc = new Pkcs1Encoding(new RsaEngine());

                else throw new Exception(MSG_INVALID_PADDING_MODE);

                BufferedAsymmetricBlockCipher bac = new BufferedAsymmetricBlockCipher(abc);

                bac.Init(_job == CryptoJob.ENCRYPT, k);

                if (sign)
                    Program.WriteAndSign(signer, bac, bac.GetBlockSize(), src, dest);

                else Program.Write(bac, bac.GetBlockSize(), src, dest, progressbar);
            }

            else
            {
                int n, l = rsa.KeySize / 8;

                if (_job == CryptoJob.ENCRYPT)
                    l -= 42;

                byte[] a = new byte[l];
                long   p = 0;
                long   z = src.Length;
                bool   b = _padding == CryptoPadding.OAEP;

                while ((n = src.Read(a, 0, l)) > 0)
                {
                    byte[] c;

                    if (n < l)
                    {
                        Array.Copy(a, c = new byte[n], l = n);
                        a = c;
                    }

                    if (_job == CryptoJob.ENCRYPT)
                    {
                        c = rsa.Encrypt(a, b);

                        if (sign)
                            signer.BlockUpdate(c, 0, c.Length);
                    }

                    else
                    {
                        c = rsa.Decrypt(a, b);

                        if (sign)
                            signer.BlockUpdate(a, 0, a.Length);
                    }

                    dest.Write(c, 0, c.Length);
                    Array.Clear(c, 0, c.Length);

                    if (progressbar)
                        Program.Progress(p += n, z, n);
                }

                if (sign)
                {
                    if (_job == CryptoJob.ENCRYPT)
                        File.WriteAllBytes(_sign, signer.GenerateSignature());

                    else Program.VerifySignature(signer);
                }
            }

            if (cleanse)
                rsa.Clear();
        }

        //----------------------------------------------------------------------------------

        private static byte[] CryptoRsa (RSACryptoServiceProvider rsa, byte[] data)
        {
            byte[]        b;
            CryptoPadding p = _padding;
            string        h = _hash;

            _padding = Program.HasRsaOaep() ? CryptoPadding.OAEP : CryptoPadding.PKCS1;
            _hash    = HASH_SHA1;

            using (MemoryStream dt = new MemoryStream(data))
            {
                using (MemoryStream bf = new MemoryStream())
                {
                    Program.CryptoRsa(rsa, dt, bf, false, false, false);
                    b = bf.ToArray();
                }
            }

            _padding = p;
            _hash    = h;

            return b;
        }

        //----------------------------------------------------------------------------------

        private static bool HasRsaOaep ()
        {
            if (_rsa_bc || Type.GetType("Mono.Runtime") != null)
                return true;

            else
	        {
	            OperatingSystem os = Environment.OSVersion;

	            switch (os.Platform)
		        {
		            case PlatformID.Win32S:
		            case PlatformID.Win32Windows:
		            case PlatformID.Win32NT:
                        return os.Version.Major > 5 || (os.Version.Major > 4 && os.Version.Minor > 0);

                    default:
                        return false;
		        }
		    }
        }

        //----------------------------------------------------------------------------------

        private static void RsaValidateKeySize ()
        {
            int min = 384;
            int max = 16384;

            if (!_rsa_bc) using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                foreach (KeySizes k in rsa.LegalKeySizes)
                {
                    min = k.MinSize;
                    max = k.MaxSize;
                }
            }

            if (_keysize == -1)
                _keysize = (short)(max > 512 ? 1024 : max);

            else if (_keysize < min || _keysize > max || _keysize % 8 != 0)
                throw new Exception(MSG_INVALID_KEY_SIZE);
        }

        //----------------------------------------------------------------------------------

        private static void RsaImportKey 
        (
              RSACryptoServiceProvider rsa
            , byte[]                   data
            , bool                     publickey
            , string                   emsg
        ){
            Program.TryBase64Decode(ref data);

            try
            {
                try
                {
                    rsa.ImportCspBlob(data);
                }

                catch (Exception)
                {
                    rsa.FromXmlString(Encoding.Default.GetString(data));
                }

                if (!publickey && rsa.PublicOnly)
                    throw new Exception(MSG_INNER_EXCEPTION_CTRL);
            }

            catch (Exception)
            {
                throw new Exception(emsg);
            }
        }

        //----------------------------------------------------------------------------------

        private static bool RsaImportKey 
        (
              RSACryptoServiceProvider rsa
            , string                   path
            , bool                     publickey
        ){
            string    se = publickey ? MSG_INVALID_PUBLIC_KEY : MSG_INVALID_PRIVATE_KEY;
            Exception ie = new Exception    
            (
                  publickey ? MSG_INVALID_PUBLIC_KEY : MSG_INVALID_PRIVATE_KEY
                , new Exception(MSG_INNER_EXCEPTION_CTRL)
            );

            if (!File.Exists(path))
                throw ie;

            byte[] data = File.ReadAllBytes(path);
 
            try
            {
                AsymmetricKeyParameter akp = Program.ImportAsymmetricKey
                (
                      data
                    , publickey
                    , se
                );

                if (!(akp is RsaKeyParameters))
                    throw ie;

                if (akp.IsPrivate)
                    Program.SetRsaFromPrivateKeyParameters(rsa, (RsaPrivateCrtKeyParameters)akp);

                else
                {
                    if (!publickey)
                        throw ie;

                    Program.SetRsaFromPublicKeyParameters(rsa, (RsaKeyParameters)akp);
                }

                return true;
            }

            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException.Message == MSG_INNER_EXCEPTION_CTRL)
                    throw e;
            }

            Program.RsaImportKey(rsa, data, publickey, se);
            Array.Clear(data, 0, data.Length);

            return false;
        }

        //----------------------------------------------------------------------------------

        private static void ValidateKeyPairFiles (bool pbk = true, bool pvk = true)
        {
            if (pbk && !Program.ValidatePath(_public_key))
                throw new Exception(MSG_INVALID_PUBLIC_KEY);

            if (pvk && !Program.ValidatePath(_private_key))
                throw new Exception(MSG_INVALID_PRIVATE_KEY);

            Program.OverwriteFileCheck(_public_key);
            Program.OverwriteFileCheck(_private_key);
        }

        //----------------------------------------------------------------------------------

        private static AsymmetricCipherKeyPair RsaBouncyCastleKeyPairGen (short size)
        {
            if (_public_exponent == 0)
                _public_exponent = 0x10001;

            RsaKeyPairGenerator     kpg = new RsaKeyPairGenerator();
            KeyGenerationParameters kgp = new RsaKeyGenerationParameters
            (
                  BigInteger.ValueOf(_public_exponent)
                , new SecureRandom()
                , size
                , Program.GetPrimeCertainty(size)
            );

            kpg.Init(kgp);
            return kpg.GenerateKeyPair();
        }

        //----------------------------------------------------------------------------------

        private static void SetRsaFromPublicKeyParameters
        (
              RSACryptoServiceProvider rsa
            , RsaKeyParameters         key
        ){
            RSAParameters p = new RSAParameters();

            p.Modulus  = key.Modulus.ToByteArrayUnsigned();
            p.Exponent = key.Exponent.ToByteArrayUnsigned();

            rsa.ImportParameters(p);
        }

        //----------------------------------------------------------------------------------

        private static void SetRsaFromPrivateKeyParameters 
        (
              RSACryptoServiceProvider   rsa
            , RsaPrivateCrtKeyParameters key
        ){
            RSAParameters p = new RSAParameters();

            p.Modulus  = key.Modulus.ToByteArrayUnsigned();
            p.Exponent = key.PublicExponent.ToByteArrayUnsigned();
            p.D        = key.Exponent.ToByteArrayUnsigned();
            p.P        = key.P.ToByteArrayUnsigned();
            p.Q        = key.Q.ToByteArrayUnsigned();
            p.DP       = key.DP.ToByteArrayUnsigned();
            p.DQ       = key.DQ.ToByteArrayUnsigned();
            p.InverseQ = key.QInv.ToByteArrayUnsigned();

            rsa.ImportParameters(p);
        }

        //----------------------------------------------------------------------------------

        private static RsaKeyParameters GetRsaPublicKeyParameters (RSACryptoServiceProvider rsa)
        {
            RSAParameters p = rsa.ExportParameters(false);

            return new RsaKeyParameters
            (
                false
                , new BigInteger(1, p.Modulus)
                , new BigInteger(1, p.Exponent)
            );
        }

        //----------------------------------------------------------------------------------

        private static RsaKeyParameters GetRsaPrivateKeyParameters (RSACryptoServiceProvider rsa)
        {
            if (rsa.PublicOnly)
                throw new Exception(MSG_PUBLIC_KEY_ONLY);

            RSAParameters p = rsa.ExportParameters(true);

            return new RsaPrivateCrtKeyParameters
            (
                  new BigInteger(1, p.Modulus)
                , new BigInteger(1, p.Exponent)
                , new BigInteger(1, p.D)
                , new BigInteger(1, p.P)
                , new BigInteger(1, p.Q)
                , new BigInteger(1, p.DP)
                , new BigInteger(1, p.DQ)
                , new BigInteger(1, p.InverseQ)
            );
        }

        //----------------------------------------------------------------------------------

        private static AsymmetricCipherKeyPair GetRsaAsymmetricKeyPair (RSACryptoServiceProvider rsa)
        {
            return new AsymmetricCipherKeyPair
            (
                  Program.GetRsaPublicKeyParameters(rsa)
                , rsa.PublicOnly ? null : Program.GetRsaPrivateKeyParameters(rsa)
            );
        }

        //----------------------------------------------------------------------------------

        private static void RsaKeyPairGen (RSACryptoServiceProvider rsa = null)
        {
            Program.ValidateKeyPairFiles(true, rsa == null ? true : !rsa.PublicOnly);

            if (_rsa_bc) Program.AsymmetricKeyPairGen
            (
                rsa != null ? Program.GetRsaAsymmetricKeyPair(rsa) :
                Program.RsaBouncyCastleKeyPairGen(_keysize)
            );

            else
            {
                if (rsa == null)
                    throw new Exception("Invalid Rsa service provider!");

                if (rsa.PublicOnly) Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , MSG_PUBLIC_KEY_ONLY
                );

                bool r = _format == CryptoFormat.RAW;

                switch (_format)
                {
                    case CryptoFormat.RAW:
                    case CryptoFormat.BASE64:
                        byte[] b = rsa.ExportCspBlob(false);

                        File.WriteAllBytes(_public_key, r ? b : Program.Base64Encode(b));
                        Array.Clear(b, 0, b.Length);

                        if (!rsa.PublicOnly)
                        {
                            b = rsa.ExportCspBlob(true);
                            File.WriteAllBytes(_private_key, r ? b : Program.Base64Encode(b));
                            Array.Clear(b, 0, b.Length);
                        }

                        break;

                    case CryptoFormat.XML:
                        File.WriteAllText(_public_key, rsa.ToXmlString(false));

                        if (!rsa.PublicOnly)
                            File.WriteAllText(_private_key, rsa.ToXmlString(true));

                        break;

                    default:
                        throw new Exception(MSG_INVALID_FORMAT);
                }
            }
        }

        //----------------------------------------------------------------------------------

        private static RSACryptoServiceProvider CertificateToRsa (X509Certificate2 cer, bool publickey)
        {
            if (!publickey && !cer.HasPrivateKey)
                throw new Exception("The specified certificate has no private key!");

            RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)
            (
                publickey || !cer.HasPrivateKey ? cer.PublicKey.Key : cer.PrivateKey
            );

            return rsa;
        }

        //----------------------------------------------------------------------------------

        private static RSACryptoServiceProvider GetRsaFromCertificateFile (string file, bool publickey)
        {
            X509Certificate2         cer = null;
            RSACryptoServiceProvider rsa = null;

            if (!File.Exists(file)) throw new Exception
            (
                String.Format
                (
                      MSG_FILE_WAS_NOT_FOUND
                    , Path.GetFileName(file)
                )
            );

            try
            {
                cer = new X509Certificate2
                (
                      file
                    , _password
                    , X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
                );
            }

            catch (CryptographicException e)
            {
                if (-2147024810 == Marshal.GetHRForException(e))
                {
                    if (!string.IsNullOrEmpty(_password))
                    {
                        if (_raisepwd)
                            throw new Exception(MSG_WRONG_PASSWORD);

                        Messenger.Print
                        (
                              Messenger.Icon.ERROR
                            , MSG_WRONG_PASSWORD +
                              MSG_PLEASE_TRY_AGAIN
                            , false
                            , true
                        );

                        Program.ExceptionControl(-2147024810);
                        _password = string.Empty;
                    }

                    Program.DefinePassword(true);
                    return Program.GetRsaFromCertificateFile(file, publickey);
                }
            }

            if (cer != null)
                rsa = Program.CertificateToRsa(cer, publickey);

            else                                                                                // PEM or DER format:
            {
                byte[] dat = null;
                byte[] bsd = File.ReadAllBytes(file);

                CspParameters cp = new CspParameters();
                cp.Flags = CspProviderFlags.UseMachineKeyStore;

                if (publickey)
                {
                    if ((dat = OpenSSL.GetRawData(bsd, "CERTIFICATE")) != null)
                    {
                        rsa = Program.CertificateToRsa(new X509Certificate2(dat), true);
                        Array.Clear(dat, 0, dat.Length);
                    }

                    else if ((dat = OpenSSL.GetRawData(bsd, "PUBLIC KEY")) != null)
                    {
                        OpenSSL.SetPublicKey(rsa = new RSACryptoServiceProvider(cp), dat);
                        Array.Clear(dat, 0, dat.Length);
                    }

                    else
                    {
                        Messenger.Print
                        (
                              Messenger.Icon.WARNING
                            , "No public key or certificate was found,\n" + 
                              "It will try with the private key!\n"
                        );

                        publickey = false;
                    }
                }

                if (!publickey)
                {
                    string spk = "PRIVATE KEY";
                    string cod = string.Empty;
                    string alg = string.Empty;

                    rsa = new RSACryptoServiceProvider(cp);

                    while (true)
                    {
                        try
                        {
                            if ((dat = OpenSSL.GetRawData(bsd, "ENCRYPTED " + spk)) != null)
                            {
                                Program.DefinePassword(true);
                                OpenSSL.SetEncryptedPrivateKey(rsa, dat, _password);
                            }

                            else if ((dat = OpenSSL.GetRawData(bsd, "RSA " + spk, ref cod, ref alg)) != null)
                            {
                                if (!string.IsNullOrEmpty(cod))
                                {
                                    Program.DefinePassword(true);

                                    byte[] d = dat;
                                    dat = OpenSSL.DecryptRsaPrivateKey(alg, cod, _password, d);
                                    Array.Clear(d, 0, d.Length);
                                }

                                OpenSSL.SetRsaPrivateKey(rsa, dat);
                            }

                            else if ((dat = OpenSSL.GetRawData(bsd, spk)) != null)
                                OpenSSL.SetPrivateKey(rsa, dat);

                            else throw new Exception("No private key was found!");

                            Array.Clear(dat, 0, dat.Length);
                            break;
                        }

                        catch (Exception e)
                        {
                            switch (Marshal.GetHRForException(e))
                            {
                                case -2146233296:
                                case -2146893819:
                                    if (_raisepwd)
                                        throw new Exception(MSG_WRONG_PASSWORD, e);

                                    Messenger.Print
                                    (
                                          Messenger.Icon.ERROR
                                        , MSG_WRONG_PASSWORD +
                                          MSG_PLEASE_TRY_AGAIN
                                        , false
                                        , true
                                    );

                                    Program.ExceptionControl(-2146233296);
                                    _password = string.Empty;
                                    break;

                                default:
                                    throw e;
                            }
                        }
                    }
                }

                Array.Clear(bsd, 0, bsd.Length);
            }
            
            return rsa;
        }

        //----------------------------------------------------------------------------------

        private static RSACryptoServiceProvider GetRsaFromCertificateStore 
        (
              string target
            , bool   publickey
        ){ 
            string                     ssn =  "subject name";
            string[]                   sft = { "thumbprint", ssn, ssn };
            X509Certificate2           cer = null;
            X509Certificate2Collection c2c = null;
            StoreLocation[]            loc = { StoreLocation.CurrentUser, StoreLocation.LocalMachine };
            X509FindType[]             xft = 
            { 
                  X509FindType.FindByThumbprint
                , X509FindType.FindBySubjectDistinguishedName
                , X509FindType.FindBySubjectName 
            };

            foreach (StoreLocation l in loc)
            {
                X509Store store = new X509Store(l);
                store.Open(OpenFlags.ReadOnly | OpenFlags.IncludeArchived);

                for (int i = xft.Length; --i > -1; )
                {
                    c2c = store.Certificates.Find(xft[i], target, false);

                    if (c2c.Count > 0)
                    {
                        if (c2c.Count > 1) Messenger.Print
                        (
                              Messenger.Icon.WARNING
                            , "Found several certificates with the same " + sft[i] +
                              ", only the last record will be used!"
                            , false
                            , true
                        );

                        cer = c2c[c2c.Count - 1];
                        break;
                    }
                }

                store.Close();

                if (cer != null)
                {
                    if (!publickey && cer.HasPrivateKey)
                    {
                        while (true)
                        {
                            try
                            {
                                Program.DefinePassword(true);

                                cer = new X509Certificate2
                                (
                                      cer.RawData
                                    , _password
                                    , X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
                                );

                                break;
                            }

                            catch (CryptographicException e)
                            {
                                if (-2147024810 == Marshal.GetHRForException(e))
                                {
                                    if (!string.IsNullOrEmpty(_password))
                                    {
                                        if (_raisepwd)
                                            throw new Exception(MSG_WRONG_PASSWORD, e);

                                        Messenger.Print
                                        (
                                              Messenger.Icon.ERROR
                                            , MSG_WRONG_PASSWORD +
                                              MSG_PLEASE_TRY_AGAIN
                                            , false
                                            , true
                                        );

                                        Program.ExceptionControl(-2147024810);
                                        _password = string.Empty;
                                    }
                                }

                                else throw e;
                            }
                        }
                    }

                    return Program.CertificateToRsa(cer, publickey);
                }
            }

            throw new Exception("\"" + target + "\" certificate was not found!");
        }

        //----------------------------------------------------------------------------------

        private static RSACryptoServiceProvider GetRsaFromCertificates 
        (
              byte index
            , bool publickey
        ){
            byte l = (byte)_cer.Count;

            if (l < 1)
                throw new Exception("No certificates available!");

            AbstractCertificate lc = _cer[index > --l ? l : index];

            if (++l > 1) foreach (AbstractCertificate t in _cer)
            {
                if ((t.type == 1 && publickey) || (t.type == 2 && !publickey))
                {
                    lc = t;
                    break;
                }
            }

            if (lc.store)
                return Program.GetRsaFromCertificateStore(lc.target, publickey);

            return Program.GetRsaFromCertificateFile(lc.target, publickey);
        }

        //----------------------------------------------------------------------------------

        private static byte GetPrimeCertainty 
        (
              short size
            , short minor    = 384
            , long  exponent = 0x10001
            , bool  expasmax = false
            , bool  rsafixed = true
        ){
            if (_certainty != 0)
                return _certainty;

            if (minor > exponent)
                throw new Exception("The minor value is greater than the exponent!");

            byte n;

            if (expasmax)
                n = (byte)Math.Floor((double)(exponent - size) / (exponent - minor) * 100);

            else
            {
                long p = _public_exponent > 0 ? _public_exponent : exponent;
                n = (byte)Math.Floor((double)(exponent / p * minor) / size * 100);

                if (rsafixed && exponent + p == 0x20002 && minor == 384)
                {
                    if (n < 4)
                        --n;

                    else if (n > 4)
                    {
                        if (size < 752)
                        {
                            if (size > minor)
                                n -= 10;

                            if (n < 46)
                                n -= 10;

                        }

                        else
                        {
                            n >>= 1;

                            if (n > 8 && n < 90)
                                n += 2;
                        }

                        if (n % 2 != 0)
                            ++n;
                    }
                }
            }

            if (n > 100)
                n = 100;

            else if (n < 1)
                n = 1;

            return n;
        }

        //----------------------------------------------------------------------------------

        private static void DisplayCurveNames ()
        {
            Program.ShowBanner();

            if (string.IsNullOrEmpty(_curvestore))
                throw new Exception("No curve store name were specified!");

            IEnumerable e;

            switch (_curvestore)
            {
                case CUSTOM:
                    e = CustomNamedCurves.Names;
                    break;

                case ANSSI:
                    e = AnssiNamedCurves.Names;
                    break;

                case TELETRUST:
                    e = TeleTrusTNamedCurves.Names;
                    break;

                case NIST:
                    e = NistNamedCurves.Names;
                    break;

                case SEC:
                    e = SecNamedCurves.Names;
                    break;

                case X962:
                    e = X962NamedCurves.Names;
                    break;

                case GOST:
                    e = ECGost3410NamedCurves.Names;
                    break;

                default:
                    throw new Exception(MSG_INVALID_CURVE_STORE);
            }

            string t;
            string s = string.Empty;
            int    l = 0;

            foreach (string n in e)
                if (l < n.Length)
                    l = n.Length;

           ++l;

            int w = Messenger.MaxBufferWidth - 3;
            int b = w / l;
            int r = w % l;
            int x = 0;

            l += r / b;
            s += "\n  ";

            foreach (string n in e)
            {
                if (++x > b)
                {
                    x  = 1;
                    s += "\n\n  ";
                }

                t = n;
                while (t.Length < l)
                    t += ' ';

                s += t;
            }

            Console.WriteLine(s);
        }

        //----------------------------------------------------------------------------------

        private static string GetCurveStoreName (string curve) 
        {
            string[] s = { CUSTOM, ANSSI, TELETRUST, NIST, SEC, X962, GOST };

            for (byte i = 0, l = (byte)s.Length; i < l; ++i)
            {
                IEnumerable e = null;

                switch (s[i])
                {
                    case CUSTOM:
                        e = CustomNamedCurves.Names;
                        break;

                    case ANSSI:
                        e = AnssiNamedCurves.Names;
                        break;

                    case TELETRUST:
                        e = TeleTrusTNamedCurves.Names;
                        break;

                    case NIST:
                        e = NistNamedCurves.Names;
                        break;

                    case SEC:
                        e = SecNamedCurves.Names;
                        break;

                    case X962:
                        e = X962NamedCurves.Names;
                        break;

                    case GOST:
                        e = ECGost3410NamedCurves.Names;
                        break;
                }

                foreach (string c in e)
                    if (c.Equals(curve, StringComparison.InvariantCultureIgnoreCase))
                        return s[i];
            }

            throw new Exception(MSG_INVALID_CURVE_STORE);
        }

        //----------------------------------------------------------------------------------

        private static AbstractCurve GetAbstractCurve ()
        {
            byte l = (byte)_curve.Count;

            if (l < 1)
                throw new Exception("No curves were specified!");

            else if (l > 1 && (_mode != PGP || _pgp_master != ECDSA || (_pgp_algorithm == ECDH && _keysize != -1)))
                _curve.RemoveAt(0);

            AbstractCurve ac = _curve[0];

            if (l > 1)
                _curve.RemoveAt(0);

            return ac;
        }

        //----------------------------------------------------------------------------------
        
        private static AsymmetricCipherKeyPair GetCurveKeyPair (string algorithm)
        {
            AbstractCurve       ac  = Program.GetAbstractCurve();
            DerObjectIdentifier oid = null;

            switch (ac.store)
            {
                case CUSTOM:
                    oid = CustomNamedCurves.GetOid(ac.name);
                    break;

                case ANSSI:
                    oid = AnssiNamedCurves.GetOid(ac.name);
                    break;

                case TELETRUST:
                    oid = TeleTrusTNamedCurves.GetOid(ac.name);
                    break;

                case NIST:
                    oid = NistNamedCurves.GetOid(ac.name);
                    break;

                case SEC:
                    oid = SecNamedCurves.GetOid(ac.name);
                    break;

                case X962:
                    oid = X962NamedCurves.GetOid(ac.name);
                    break;

                case GOST:
                    oid = ECGost3410NamedCurves.GetOid(ac.name);
                    break;

                default:
                    throw new Exception(MSG_INVALID_CURVE_STORE);
            }

            if (oid == null)
                throw new Exception("Curve not found!");

            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator(algorithm);

            kpg.Init(new ECKeyGenerationParameters(oid, new SecureRandom()));
            return kpg.GenerateKeyPair();
        }

        //----------------------------------------------------------------------------------

        private static AsymmetricCipherKeyPair EcdhKeyPairGen (bool save = false)
        {
            AsymmetricCipherKeyPair akp;

            if (_keysize == -1)
                akp = Program.GetCurveKeyPair(ECDH);

            else
            {
                switch (_keysize)
                {
                    case 192:
                    case 224:
                    case 239:
                    case 256:
                    case 384:
                    case 521:
                        break;

                    default:
                        throw new Exception(MSG_INVALID_KEY_SIZE);
                }

                IAsymmetricCipherKeyPairGenerator akpg = GeneratorUtilities.GetKeyPairGenerator(ECDH);
                DHParametersGenerator             dhpg = new DHParametersGenerator();

                dhpg.Init(_keysize, Program.GetPrimeCertainty(_keysize, 192, 521, true), new SecureRandom());
                DHKeyGenerationParameters kgp = new DHKeyGenerationParameters
                (
                      new SecureRandom()
                    , dhpg.GenerateParameters()
                );

                akpg.Init(kgp);
                akp = akpg.GenerateKeyPair();
            }

            if (save)
            {
                Program.ValidateKeyPairFiles();
                Program.AsymmetricKeyPairGen(akp);
            }

            return akp;
        }

        //----------------------------------------------------------------------------------

        private static void EcdhKeyPairGen (AsymmetricCipherKeyPair akp)
        {
            if (!(akp.Public is ECPublicKeyParameters))
                throw new Exception(MSG_INVALID_PUBLIC_KEY);

            if (!(akp.Private is ECPrivateKeyParameters))
                throw new Exception(MSG_INVALID_PRIVATE_KEY);

            Program.ValidateKeyPairFiles();
            Program.AsymmetricKeyPairGen(akp);
        }

        //----------------------------------------------------------------------------------

        private static PgpKeyRingGenerator RsaMasterKeyGen ()
        {
            return new PgpKeyRingGenerator
            (
                  PgpSignature.DefaultCertification
                , new PgpKeyPair
                  (
                        PublicKeyAlgorithmTag.RsaSign
                      , Program.RsaBouncyCastleKeyPairGen(1024)
                      , DateTime.Now
                  )
                , _pgp_id
                , _ska
                , _password.ToCharArray()
                , _sha1
                , null
                , null
                , new SecureRandom()
            );
        }

        //----------------------------------------------------------------------------------

        private static PgpKeyRingGenerator DsaMasterKeyGen()
        {
            DsaKeyPairGenerator        kpg = new DsaKeyPairGenerator();
            DsaParametersGenerator     dpg = new DsaParametersGenerator();
            DsaKeyGenerationParameters kgp;

            dpg.Init(1024, 64, new SecureRandom());
            kgp = new DsaKeyGenerationParameters(new SecureRandom(), dpg.GenerateParameters());
            kpg.Init(kgp);

            return new PgpKeyRingGenerator
            (
                  PgpSignature.DefaultCertification
                , new PgpKeyPair
                  (
                        PublicKeyAlgorithmTag.Dsa
                      , kpg.GenerateKeyPair()
                      , DateTime.Now
                  )
                , _pgp_id
                , _ska
                , _password.ToCharArray()
                , _sha1
                , null
                , null
                , new SecureRandom()
            );
        }

        //----------------------------------------------------------------------------------

        private static PgpKeyRingGenerator EcdsaMasterKeyGen ()
        {
            return new PgpKeyRingGenerator
            (
                  PgpSignature.DefaultCertification
                , new PgpKeyPair
                  (
                        PublicKeyAlgorithmTag.ECDsa
                      , Program.GetCurveKeyPair(ECDSA)
                      , DateTime.Now
                  )
                , _pgp_id
                , _ska
                , _password.ToCharArray()
                , _sha1
                , null
                , null
                , new SecureRandom()
            );
        }

        //----------------------------------------------------------------------------------

        private static PgpKeyRingGenerator MasterKeyGen ()
        {
            switch (_pgp_master)
            {
                case RSA:
                    return Program.RsaMasterKeyGen();

                case DSA:
                    return Program.DsaMasterKeyGen();

                case ECDSA:
                    return Program.EcdsaMasterKeyGen();

                default:
                    throw new Exception("Invalid Pgp master key type!");
            }
        }


        //----------------------------------------------------------------------------------

        private static PgpSecretKey GetPgpSecretKey (RSACryptoServiceProvider rsa)
        {
            return new PgpSecretKey
            (
                  PgpSignature.DefaultCertification
                , new PgpKeyPair
                  (
                        Program.GetPgpPublicKeyFromRsa(rsa)
                      , Program.GetPgpPrivateKeyFromRsa(rsa)
                  )
                , _pgp_id
                , _ska
                , _password.ToCharArray()
                , _sha1
                , null
                , null
                , new SecureRandom()
           );
        }

        //----------------------------------------------------------------------------------

        private static void PgpRsaKeyPairGen
        (
              bool                     armored
            , RSACryptoServiceProvider guest = null
        ){
            PgpSecretKey psk = null;
            PgpPublicKey pbk = null;

            if (guest != null)
            {
                Program.ValidateKeyPairFiles(true, !guest.PublicOnly);

                if (!guest.PublicOnly)
                {
                    Program.DefinePassword(true);
                    psk = Program.GetPgpSecretKey(guest);
                }

                else
                {
                    Messenger.Print(Messenger.Icon.WARNING, MSG_PUBLIC_KEY_ONLY);
                    pbk = Program.GetPgpPublicKeyFromRsa(guest);
                }
            }

            else
            {
                Program.ValidateKeyPairFiles();
                Program.RsaValidateKeySize();
                Program.DefinePassword(true);

                if (_rsa_bc) psk = new PgpSecretKey
                (
                      PgpSignature.DefaultCertification
                    , new PgpKeyPair
                      (
                            PublicKeyAlgorithmTag.RsaGeneral
                          , Program.RsaBouncyCastleKeyPairGen(_keysize)
                          , DateTime.Now
                      )
                    , _pgp_id
                    , _ska
                    , _password.ToCharArray()
                    , _sha1
                    , null
                    , null
                    , new SecureRandom()
                );

                else using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(_keysize))
                    psk = Program.GetPgpSecretKey(rsa);
            }

            if (_pgp_master == RSA)
            {
                if (psk != null)
                {
                    using (FileStream fspvk = File.Create(_private_key))
                        using (Stream stm = armored ? (Stream)new ArmoredOutputStream(fspvk) : fspvk)
                            psk.Encode(stm);

                    
                    pbk = psk.PublicKey;
                }

                if (pbk != null)
                    using (FileStream fspbk = File.Create(_public_key))
                        using (Stream stm = armored ? (Stream)new ArmoredOutputStream(fspbk) : fspbk)
                            pbk.Encode(stm);
            }

            else 
            {
                if (psk == null)
                    throw new Exception(MSG_INVALID_PRIVATE_KEY);

                PgpKeyRingGenerator krg = Program.MasterKeyGen();
                PgpPrivateKey       pvk = psk.ExtractPrivateKey(_password.ToCharArray());

                if (pbk == null)
                    pbk = psk.PublicKey;

                krg.AddSubKey(new PgpKeyPair(pbk, pvk));

                using (FileStream fspvk = File.Create(_private_key))
                    using (Stream stm = armored ? (Stream)new ArmoredOutputStream(fspvk) : fspvk)
                        krg.GenerateSecretKeyRing().Encode(stm);

                using (FileStream fspbk = File.Create(_public_key))
                    using (Stream stm = armored ? (Stream)new ArmoredOutputStream(fspbk) : fspbk)
                        krg.GeneratePublicKeyRing().Encode(stm);
            }
        }

        //----------------------------------------------------------------------------------

        private static void PgpElGamalKeyPairGen
        (
              bool                    armored
            , AsymmetricCipherKeyPair guest = null
        ){
            Program.ValidateKeyPairFiles();

            if (guest != null)
            {
                if 
                (
                    guest.Private == null || !(guest.Private is ElGamalPrivateKeyParameters) || 
                    guest.Public  == null || !(guest.Public  is ElGamalPublicKeyParameters)
                ){
                    throw new Exception(MSG_INVALID_KEY_PAIR);
                }
            }

            else guest = ElGamalKeyPairGen(false);

            PgpKeyPair kp = new PgpKeyPair
            (
                  PublicKeyAlgorithmTag.ElGamalGeneral
                , guest
                , DateTime.Now
            );
            
            if (!Program.IsReciprocalPgpKeys(kp.PublicKey, kp.PrivateKey))
                throw new Exception(MSG_NON_RECIPROCAL_KEYS);

            Program.DefinePassword(true);
            if (string.IsNullOrEmpty(_pgp_master))
                _pgp_master = DSA;

            PgpKeyRingGenerator krg = Program.MasterKeyGen();

            krg.AddSubKey(kp);
            using (FileStream fspvk = File.Create(_private_key))
                using (Stream stm = armored ? (Stream)new ArmoredOutputStream(fspvk) : fspvk)
                    krg.GenerateSecretKeyRing().Encode(stm);

            using (FileStream fspbk = File.Create(_public_key))
                using (Stream stm = armored ? (Stream)new ArmoredOutputStream(fspbk) : fspbk)
                    krg.GeneratePublicKeyRing().Encode(stm);
        }

        //----------------------------------------------------------------------------------

        private static void PgpEcdhKeyPairGen (bool armored, AsymmetricCipherKeyPair guest = null)
        {
            if (guest == null)
                guest = Program.EcdhKeyPairGen();

            else
            {
                if (guest.Public == null || !(guest.Public is ECPublicKeyParameters))
                    throw new Exception(MSG_INVALID_PUBLIC_KEY);

                if (guest.Private == null || !(guest.Private is ECPrivateKeyParameters))
                    throw new Exception(MSG_INVALID_PRIVATE_KEY);
            }

            Program.ValidateKeyPairFiles();
            
            PgpKeyPair kp = new PgpKeyPair
            (
                  PublicKeyAlgorithmTag.ECDH
                , guest ?? Program.EcdhKeyPairGen()
                , DateTime.Now
            );

            if (!Program.IsReciprocalPgpKeys(kp.PublicKey, kp.PrivateKey))
                throw new Exception(MSG_NON_RECIPROCAL_KEYS);

            Program.DefinePassword(true);
            if (string.IsNullOrEmpty(_pgp_master))
                _pgp_master = ECDSA;

            PgpKeyRingGenerator krg = Program.MasterKeyGen();

            krg.AddSubKey(kp);
            using (FileStream fspvk = File.Create(_private_key))
                using (Stream stm = armored ? (Stream)new ArmoredOutputStream(fspvk) : fspvk)
                    krg.GenerateSecretKeyRing().Encode(stm);

            using (FileStream fspbk = File.Create(_public_key))
                using (Stream stm = armored ? (Stream)new ArmoredOutputStream(fspbk) : fspbk)
                    krg.GeneratePublicKeyRing().Encode(stm);
        }

        //----------------------------------------------------------------------------------

        private static PgpPublicKey GetPgpPublicKey (bool master = false)
        {
            if (!File.Exists(_public_key))
                throw new Exception(MSG_INVALID_PUBLIC_KEY);

            using (Stream f = File.OpenRead(_public_key))
            {
                using (Stream i = PgpUtilities.GetDecoderStream(f))
                {
                    PgpPublicKeyRingBundle prb = new PgpPublicKeyRingBundle(i);

                    foreach (PgpPublicKeyRing pkr in prb.GetKeyRings())
                        foreach (PgpPublicKey pbk in pkr.GetPublicKeys())
                            if ((master && pbk.IsMasterKey) || pbk.IsEncryptionKey)
                                return pbk;
                }
            }

            throw new Exception(string.Format(MSG_NO_PGP_KEY_FOUND, "public"));
        }
        
        //----------------------------------------------------------------------------------

        private static PgpPrivateKey GetPgpPrivateKey (bool master = false)
        {
            if (!File.Exists(_private_key))
                throw new Exception(MSG_INVALID_PRIVATE_KEY);

            using (Stream f = File.OpenRead(_private_key))
            {
                using (Stream i = PgpUtilities.GetDecoderStream(f))
                {
                    PgpSecretKeyRingBundle skb = new PgpSecretKeyRingBundle(i);

                    foreach (PgpSecretKeyRing skr in skb.GetKeyRings())
                    {
                        foreach (PgpSecretKey psk in skr.GetSecretKeys())
                        {
                            if (psk.IsPrivateKeyEmpty)
                                continue;

                            else if (!master && psk.IsMasterKey)
                                if (psk.PublicKey.Algorithm != PublicKeyAlgorithmTag.RsaGeneral)
                                    continue;

                            while (true)
                            {
                                try
                                {
                                    Program.DefinePassword(true);
                                    PgpPrivateKey pvk = psk.ExtractPrivateKey(_password.ToCharArray());

                                    //_hasprivatekey = true;
                                    return pvk;
                                }

                                catch (PgpException e)
                                {
                                    if (!e.Message.StartsWith("Checksum mismatch"))
                                        throw e;

                                    else
                                    {
                                        if (_raisepwd)
                                            throw new Exception(MSG_WRONG_PASSWORD);

                                        Messenger.Print
                                        (
                                              Messenger.Icon.ERROR
                                            , MSG_WRONG_PASSWORD +
                                              MSG_PLEASE_TRY_AGAIN
                                            , false
                                            , true
                                        );

                                        Program.ExceptionControl(-2146233088);
                                        _password = string.Empty;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            throw new Exception(string.Format(MSG_NO_PGP_KEY_FOUND, "private"));
        }

       //----------------------------------------------------------------------------------

        private static bool IsReciprocalPgpKeys (PgpPublicKey pbk, PgpPrivateKey pvk)
        {
            if (pbk.PublicKeyPacket.Algorithm != pvk.PublicKeyPacket.Algorithm)
                return false;

            RsaPublicBcpgKey      rsapbk;
            RsaPublicBcpgKey      rsapvk;
            DsaPublicBcpgKey      dsapbk;
            DsaPublicBcpgKey      dsapvk;
            ElGamalPublicBcpgKey  elgpbk;
            ElGamalPublicBcpgKey  elgpvk;
            ECDHPublicBcpgKey     ecpbkp;
            ECDHPublicBcpgKey     ecpvkp;

            switch (pbk.PublicKeyPacket.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                    rsapbk = (RsaPublicBcpgKey)pbk.PublicKeyPacket.Key;
                    rsapvk = (RsaPublicBcpgKey)pvk.PublicKeyPacket.Key;

                    if (rsapbk.Modulus.CompareTo(rsapvk.Modulus) != 0)
                        return false;

                    if (rsapbk.PublicExponent.CompareTo(rsapvk.PublicExponent) != 0)
                        return false;
                    
                    break;

                case PublicKeyAlgorithmTag.ECDsa:
                    dsapbk = (DsaPublicBcpgKey)pbk.PublicKeyPacket.Key;
                    dsapvk = (DsaPublicBcpgKey)pvk.PublicKeyPacket.Key;

                    if (dsapbk.G.CompareTo(dsapvk.G) != 0)
                        return false;

                    if (dsapbk.P.CompareTo(dsapvk.P) != 0)
                        return false;

                    if (dsapbk.Q.CompareTo(dsapvk.Q) != 0)
                        return false;

                    if (dsapbk.Y.CompareTo(dsapvk.Y) != 0)
                        return false;

                    break;
                  
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    elgpbk = (ElGamalPublicBcpgKey)pbk.PublicKeyPacket.Key;
                    elgpvk = (ElGamalPublicBcpgKey)pvk.PublicKeyPacket.Key;

                    if (elgpbk.G.CompareTo(elgpvk.G) != 0)
                        return false;

                    if (elgpbk.P.CompareTo(elgpvk.P) != 0)
                        return false;

                    if (elgpbk.Y.CompareTo(elgpvk.Y) != 0)
                        return false;

                    break;

                case PublicKeyAlgorithmTag.ECDH:
                    ecpbkp = (ECDHPublicBcpgKey)pbk.PublicKeyPacket.Key;
                    ecpvkp = (ECDHPublicBcpgKey)pvk.PublicKeyPacket.Key;

                    if (ecpbkp.HashAlgorithm != ecpvkp.HashAlgorithm)
                        return false;

                    if (ecpbkp.SymmetricKeyAlgorithm != ecpvkp.SymmetricKeyAlgorithm)
                        return false;

                    if (ecpbkp.EncodedPoint.CompareTo(ecpvkp.EncodedPoint) != 0)
                        return false;

                    byte[] a = ecpbkp.CurveOid.GetEncoded();
                    byte[] b = ecpvkp.CurveOid.GetEncoded();

                    try
                    {
                        if (!Arrays.AreEqual(a, b))
                            return false;
                    }

                    finally
                    {
                        Array.Clear(a, 0, a.Length);
                        Array.Clear(b, 0, b.Length);
                    }

                    break;

                default:
                    throw new IOException("Unsupported Pgp algorithm!");
            }

            return true;
        }


        //----------------------------------------------------------------------------------

        private static PgpPublicKey GetPgpPublicKeyFromRsa (RSACryptoServiceProvider rsa)
        {
            RSAParameters p = rsa.ExportParameters(false);

            return new PgpPublicKey
            (
                  PublicKeyAlgorithmTag.RsaGeneral
                , Program.GetRsaPublicKeyParameters(rsa)
                , DateTime.Now
            );
        }
        
        //----------------------------------------------------------------------------------

        private static PgpPrivateKey GetPgpPrivateKeyFromRsa (RSACryptoServiceProvider rsa)
        {
            if (rsa.PublicOnly)
                throw new Exception(MSG_PUBLIC_KEY_ONLY);

            PgpPublicKey  t = Program.GetPgpPublicKeyFromRsa(rsa);
            RSAParameters p = rsa.ExportParameters(true);

            return new PgpPrivateKey
            (
                  t.KeyId
                , t.PublicKeyPacket
                , Program.GetRsaPrivateKeyParameters(rsa)
            );
        }
        
        //----------------------------------------------------------------------------------

        private static void PgpPublicKeyToRsa (PgpPublicKey pbk, RSACryptoServiceProvider rsa)
        {
            switch (pbk.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                    RsaKeyParameters k = (RsaKeyParameters)pbk.GetKey();
                    RSAParameters    p = new RSAParameters();

                    p.Modulus  = k.Modulus.ToByteArrayUnsigned();
                    p.Exponent = k.Exponent.ToByteArrayUnsigned();

                    rsa.ImportParameters(p);
                    break;

                default:
                    throw new Exception(MSG_INVALID_RSA_KEY);
            }
        }
        
        //----------------------------------------------------------------------------------

        private static void PgpPrivateKeyToRsa (PgpPrivateKey pvk, RSACryptoServiceProvider rsa)
        {
            switch (pvk.PublicKeyPacket.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                    RsaPrivateCrtKeyParameters k = (RsaPrivateCrtKeyParameters)pvk.Key;
                    RSAParameters              p = new RSAParameters();

                    p.Modulus  = k.Modulus.ToByteArrayUnsigned();
                    p.Exponent = k.PublicExponent.ToByteArrayUnsigned();
                    p.D        = k.Exponent.ToByteArrayUnsigned();
                    p.P        = k.P.ToByteArrayUnsigned();
                    p.Q        = k.Q.ToByteArrayUnsigned();
                    p.DP       = k.DP.ToByteArrayUnsigned();
                    p.DQ       = k.DQ.ToByteArrayUnsigned();
                    p.InverseQ = k.QInv.ToByteArrayUnsigned();

                    rsa.ImportParameters(p);
                    break;

                default:
                    throw new Exception(MSG_INVALID_RSA_KEY);
            }
        }

        //----------------------------------------------------------------------------------

        private static PgpPublicKey GetPgpPublicKeyFromElGamal (ElGamalPublicKeyParameters pbk)
        {
            return new PgpPublicKey
            (
                  PublicKeyAlgorithmTag.ElGamalGeneral
                , pbk
                , DateTime.Now
            );
        }

        //----------------------------------------------------------------------------------

        private static PgpPrivateKey GetPgpPrivateKeyFromElGamal
        (
              ElGamalPublicKeyParameters  pbk
            , ElGamalPrivateKeyParameters pvk
        ){

            PgpPublicKey p = Program.GetPgpPublicKeyFromElGamal(pbk);

            return new PgpPrivateKey
            (
                  p.KeyId
                , p.PublicKeyPacket
                , pvk
            );
        }

        //----------------------------------------------------------------------------------

        private static ElGamalPublicKeyParameters PgpPublicKeyToElGamal (PgpPublicKey pbk)
        {
            if (pbk != null)
            {
                if (pbk.Algorithm == PublicKeyAlgorithmTag.ElGamalGeneral)
                    return (ElGamalPublicKeyParameters)pbk.GetKey();

                else throw new Exception(MSG_INVALID_ELGAMAL_KEY);
            }

            return null;
        }

        //----------------------------------------------------------------------------------

        private static ElGamalPrivateKeyParameters PgpPrivateKeyToElGamal (PgpPrivateKey pvk)
        {
            if (pvk != null)
            {
                if (pvk.Key is ElGamalPrivateKeyParameters)
                    return (ElGamalPrivateKeyParameters)pvk.Key;

                else throw new Exception(MSG_INVALID_ELGAMAL_KEY);
            }

            return null;
        }

        //----------------------------------------------------------------------------------

        private static PgpPublicKey GetPgpPublicKeyFromEcdh (ECPublicKeyParameters pbk)
        {
            return new PgpPublicKey
            (
                  PublicKeyAlgorithmTag.ECDH
                , pbk
                , DateTime.Now
            );
        }

        //----------------------------------------------------------------------------------

        private static PgpPrivateKey GetPgpPrivateKeyFromEcdh
        (
              ECPublicKeyParameters  pbk
            , ECPrivateKeyParameters pvk
        ){
            PgpPublicKey p = Program.GetPgpPublicKeyFromEcdh(pbk);

            return new PgpPrivateKey
            (
                  p.KeyId
                , p.PublicKeyPacket
                , pvk
            );
        }

        //----------------------------------------------------------------------------------

        private static ECPublicKeyParameters PgpPublicKeyToEcdh (PgpPublicKey pbk)
        {
            if (pbk != null)
            {
                if (pbk.Algorithm == PublicKeyAlgorithmTag.ECDH)
                    return (ECPublicKeyParameters)pbk.GetKey();

                else throw new Exception(MSG_INVALID_ECDH_KEY);
            }

            return null;
        }

        //----------------------------------------------------------------------------------

        private static ECPrivateKeyParameters PgpPrivateKeyToEcdh (PgpPrivateKey pvk)
        {
            if (pvk != null)
            {
                if (pvk.Key is ECPrivateKeyParameters)
                    return (ECPrivateKeyParameters)pvk.Key;

                else throw new Exception(MSG_INVALID_ECDH_KEY);
            }

            return null;
        }

        //----------------------------------------------------------------------------------

        private static void AssertPgpAlgorithm (PublicKeyAlgorithmTag pkat)
        {
            string s = " algorithm has been detected and asserted!";

            switch (pkat)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                    if (_pgp_algorithm != RSA)
                    {
                        _pgp_algorithm = RSA;
                        Messenger.Print(Messenger.Icon.WARNING, RSA + s);
                    }
                    break;

                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    if (_pgp_algorithm != ELGAMAL)
                    {
                        _pgp_algorithm = ELGAMAL;
                        Messenger.Print(Messenger.Icon.WARNING, ELGAMAL + s);
                    }
                    break;

                case PublicKeyAlgorithmTag.ECDH:
                    if (_pgp_algorithm != ECDH)
                    {
                        _pgp_algorithm = ECDH;
                        Messenger.Print(Messenger.Icon.WARNING, ECDH + s);
                    }
                    break;

                default:
                    throw new Exception(MSG_INVALID_PGP_ALGORITHM);
            }
        }

        //----------------------------------------------------------------------------------

        private static void WriteAndSign 
        (
              PgpSignatureGenerator psg
            , Stream                src
            , Stream                dest
            , Stream                compressed
            , long                  srclen
        ){
            byte[] b = new byte[_buffersize];
            long   n = 0;

            for (int c; (c = src.Read(b, 0, _buffersize)) > 0; )
            {
                dest.Write(b, 0, c);
                psg.Update(b, 0, c);
                Program.Progress(n += c, srclen, c);
            }

            Array.Clear(b, 0, b.Length);
            psg.Generate().Encode(compressed);

            if (_percent < 100)
                Program.Progress(srclen, srclen, 0);
        }

        //----------------------------------------------------------------------------------

        private static void WriteAndSign 
        (
              PgpOnePassSignature ops
            , Stream              src
            , Stream              dest
            , long                srclen
        ){
            byte[] b = new byte[_buffersize];
            long   n = 0;

            for (int c; (c = src.Read(b, 0, _buffersize)) > 0; )
            {
                dest.Write(b, 0, c);
                ops.Update(b, 0, c);

                Program.Progress(n += c, srclen, c);
            }

            Array.Clear(b, 0, b.Length);

            if (_percent < 100)
                Program.Progress(srclen, srclen, 0);
        }

        //----------------------------------------------------------------------------------

        private static void PgpEncrypt 
        (
              Stream       src
            , Stream       dest
            , string       name
            , bool         armoed
            , bool         check
        ){
            byte[]                     ebf = new byte[_buffersize];
            PgpLiteralDataGenerator    ldg = new PgpLiteralDataGenerator();
            PgpCompressedDataGenerator cdg = new PgpCompressedDataGenerator(_cat);
            PgpEncryptedDataGenerator  edg = new PgpEncryptedDataGenerator(_ska, check, new SecureRandom());
            PgpSignatureGenerator      psg = null;
            HashAlgorithmTag           hat = HashAlgorithmTag.Sha512;

            edg.AddMethod(_pgp_pbk);

            using (Stream os = armoed ? new ArmoredOutputStream(dest) : dest)
            {
                using (Stream es = edg.Open(os, ebf))
                {
                    using (Stream cs = cdg.Open(es))
                    {
                        if (_pgp_sign)
                        {
                            if (_pgp_pvk == null)
                                throw new Exception(MSG_INVALID_PRIVATE_KEY);

                            switch (_hash)
                            {
                                case HASH_SHA1:
                                    hat = HashAlgorithmTag.Sha1;
                                    break;

                                case HASH_SHA224:
                                    hat = HashAlgorithmTag.Sha224;
                                    break;

                                case HASH_SHA256:
                                    hat = HashAlgorithmTag.Sha256;
                                    break;

                                case HASH_SHA384:
                                    hat = HashAlgorithmTag.Sha384;
                                    break;

                                case HASH_SHA512:
                                    break;

                                case HASH_MD2:
                                    hat = HashAlgorithmTag.MD2;
                                    break;

                                case HASH_MD5:
                                    hat = HashAlgorithmTag.MD5;
                                    break;

                                case HASH_RIPEMD160:
                                    hat = HashAlgorithmTag.RipeMD160;
                                    break;

                                default:
                                    throw new Exception(MSG_INVALID_HASH);
                            }

                            psg = new PgpSignatureGenerator(_pgp_pvk.PublicKeyPacket.Algorithm, hat);
                            psg.InitSign(PgpSignature.BinaryDocument, _pgp_pvk);

                            foreach (string uid in _pgp_pbk.GetUserIds())
                            {
                                PgpSignatureSubpacketGenerator ssg = new PgpSignatureSubpacketGenerator();

                                ssg.SetSignerUserId(false, uid);
                                psg.SetHashedSubpackets(ssg.Generate());
                                break;
                            }

                            psg.GenerateOnePassVersion(false).Encode(cs);
                        }

                        using (Stream ls = ldg.Open(cs, PgpLiteralData.Binary, name, src.Length, DateTime.Now))
                        {
                            if (_pgp_sign)
                                Program.WriteAndSign(psg, src, ls, cs, src.Length);

                            else Program.Write(src, ls, src.Length);

                            ldg.Close();
                            cdg.Close();
                            edg.Close();
                        }
                    }
                }
            }

            Array.Clear(ebf, 0, ebf.Length);
        }

		//----------------------------------------------------------------------------------

        private static void PgpDecrypt (Stream src, Stream dest)
        {
            using (Stream sis = PgpUtilities.GetDecoderStream(src))
            {
                PgpObjectFactory     of = new PgpObjectFactory(sis);
                PgpObject            po = null;
                PgpEncryptedDataList ed = null;
                PgpLiteralData       ld = null;
                PgpOnePassSignature  ps = null;
                PgpSignatureList     sl = null;

                while (ed == null && (po = of.NextPgpObject()) != null)
                    if (po is PgpEncryptedDataList)
                        ed = (PgpEncryptedDataList)po;

                if (ed == null || ed.IsEmpty)
                    throw new Exception("No Pgp encrypted data found!");

                foreach (PgpPublicKeyEncryptedData pd in ed.GetEncryptedDataObjects())
                {
                    byte nf = 1;

                    using (Stream ds = pd.GetDataStream(_pgp_pvk))
                    {
                        of = new PgpObjectFactory(ds);

                        if ((po = of.NextPgpObject()) is PgpCompressedData)
                        {
                            using (Stream tmp = ((PgpCompressedData)po).GetDataStream())
                            {
                                of = new PgpObjectFactory(tmp);

                                if ((po = of.NextPgpObject()) is PgpOnePassSignatureList)
                                {
                                    if (_pgp_sign)
                                    {
                                        if (_pgp_pbk == null)
                                            throw new Exception(MSG_INVALID_PUBLIC_KEY);

                                        if (((PgpOnePassSignatureList)po).Count > 0)
                                        {
                                            ps = ((PgpOnePassSignatureList)po)[0];
                                            ps.InitVerify(_pgp_pbk);
                                        }
                                    }

                                    if ((po = of.NextPgpObject()) is PgpLiteralData)
                                        ld = (PgpLiteralData)po;

                                    else Messenger.Print
                                    (
                                          Messenger.Icon.WARNING
                                        , "The input file contains signed data but not literal data!"
                                        , false
                                        , true
                                    );
                                }

                                else if (po is PgpLiteralData)
                                    ld = (PgpLiteralData)po;
                            }

                            nf = 2;
                        }

                        else if (po is PgpLiteralData)
                            ld = (PgpLiteralData)po;

                        if (ld == null)
                            continue;

                        using (Stream so = ld.GetInputStream())
                        {
                            if (_pgp_sign && ps != null)
                            {
                                Program.WriteAndSign(ps, so, dest, src.Length * nf);

                                if ((po = of.NextPgpObject()) is PgpSignatureList)
                                    sl = (PgpSignatureList)po;
                            }

                            else Program.Write(so, dest, src.Length * nf);
                        }

                        if (pd.IsIntegrityProtected() && !pd.Verify())
                            throw new Exception("Pgp data integrity check fails!");

                        break;
                    }
                }

                if (ld == null)
                    throw new Exception("The input file does not contain any literal data!");

                else if (_pgp_sign)
                {
                    string s = "Pgp signature verification ";

                    if (ps == null || sl == null || sl.Count < 1 || !ps.Verify((PgpSignature)sl[0]))
                        throw new Exception(s + "failed!");

         		    else Messenger.Print
                    (
                          Messenger.Icon.INFORMATION
                        , s + "success!"
                        , false
                        , true
                    );
         	    }
            }
        }

        //----------------------------------------------------------------------------------

        private static void Write (BufferedBlockCipher bc, Stream src, Stream dest, int offset)
        {
            byte[] i = new byte[_buffersize];
            byte[] o = new byte[bc.GetBlockSize() + bc.GetOutputSize(_buffersize)];
            long   l = src.Length;
            long   p = offset;
            int    n;

            while ((n = src.Read(i, 0, i.Length)) > 0)
            {
                dest.Write(o, 0, bc.ProcessBytes(i, 0, n, o, 0));
                Program.Progress(p += n, l, n);
            }

            if ((n = bc.DoFinal(o, 0)) > 0)
                dest.Write(o, 0, n);

            Array.Clear(i, 0, i.Length);
            Array.Clear(o, 0, o.Length);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoCamellia 
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new CamelliaEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoSerpent
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new SerpentEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoTnepres
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new TnepresEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoTwofish        
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new TwofishEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoBlowfish
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new BlowfishEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoThreefish
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , !_without_iv
            );

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new ThreefishEngine(_keysize))
                , Program.GetBouncyCastlePadding()
            );

            ICipherParameters cp;

            if (_without_iv)
                 cp = new KeyParameter(_sk.key);

            else cp = new TweakableBlockCipherParameters(new KeyParameter(_sk.key), _sk.iv);

            bc.Init(encryption, cp);
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoCast5
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new Cast5Engine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoCast6
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new Cast6Engine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoIdea
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new IdeaEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoNoekeon
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new NoekeonEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoSeed
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new SeedEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoGost
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new Gost28147Engine())
                , Program.GetBouncyCastlePadding()
            );

            if (string.IsNullOrEmpty(_sbox))
                bc.Init(encryption, new KeyParameter(_sk.key));

            else bc.Init
            (
                  encryption
                , new ParametersWithSBox
                  (
                        new KeyParameter(_sk.key)
                      , _sk.iv ?? Gost28147Engine.GetSBox(_sbox)
                  )
            );

            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoTea
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new TeaEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoXTea
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new XteaEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }
        
        //----------------------------------------------------------------------------------

        private static void CryptoSkipjack
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new SkipjackEngine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoRc5
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(_rc5b64 ? (IBlockCipher)new RC564Engine() : new RC532Engine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new RC5Parameters(_sk.key, _rounds));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoRc6
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            BufferedBlockCipher bc = new PaddedBufferedBlockCipher
            (
                  Program.GetBlockCipherMode(new RC6Engine())
                , Program.GetBouncyCastlePadding()
            );

            bc.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(bc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void Write (IStreamCipher sc, Stream src, Stream dest, int offset)
        {
            byte[] i = new byte[_buffersize];
            byte[] o = new byte[_buffersize];
            long   l = src.Length - offset;
            long   p = 0;

            for (int n; (n = src.Read(i, 0, i.Length)) > 0; )
            {
                sc.ProcessBytes(i, 0, n, o, 0);
                dest.Write(o, 0, n);
                Program.Progress(p += n, l, n);
            }

            Array.Clear(i, 0, i.Length);
            Array.Clear(o, 0, o.Length);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoRc4 
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            RC4Engine rc4 = new RC4Engine();

            rc4.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(rc4, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoIsaac
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            
            int n = 0;

            if (provider != null)
                n = Program.ResolveKeyExchange(provider, _job == CryptoJob.ENCRYPT ? dest : src);

            IsaacEngine ie = new IsaacEngine();

            ie.Init(encryption, new KeyParameter(_sk.key));
            Program.Write(ie, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoHongjun
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            IStreamCipher hc;
            int           n = 0;

            switch (_keysize)
            {
                case 128:
                    hc = new HC128Engine();
                    break;

                case 256:
                    hc = new HC256Engine();
                    break;

                default:
                    throw new Exception(MSG_INVALID_KEY_SIZE);
            }

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , true
            );

            hc.Init(encryption, new ParametersWithIV(new KeyParameter(_sk.key), _sk.iv));
            Program.Write(hc, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoSalsa20
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){  
            int            n = 0;
            Salsa20Engine se = new Salsa20Engine(_rounds);

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , true
                , true
            );

            se.Init(encryption, new ParametersWithIV(new KeyParameter(_sk.key), _sk.iv));
            Program.Write(se, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoXSalsa20
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int             n = 0;
            XSalsa20Engine se = new XSalsa20Engine();

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , true
                , true
             );

            se.Init(encryption, new ParametersWithIV(new KeyParameter(_sk.key), _sk.iv));
            Program.Write(se, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoChaCha
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int           n = 0;
            ChaChaEngine se = new ChaChaEngine(_rounds);

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , true
                , true
            );

            se.Init(encryption, new ParametersWithIV(new KeyParameter(_sk.key), _sk.iv));
            Program.Write(se, src, dest, n);
        }

        //---------------------------------------------------------------------------------

        private static void CryptoVmpc
        (
              bool   encryption
            , Stream src
            , Stream dest
            , object provider = null
        ){
            int         n = 0;
            VmpcEngine ve = _ksa3 ? new VmpcKsa3Engine() : new VmpcEngine();

            if (provider != null) n = Program.ResolveKeyExchange
            (
                  provider
                , _job == CryptoJob.ENCRYPT ? dest : src
                , true
                , true
            );

            ve.Init(encryption, new ParametersWithIV(new KeyParameter(_sk.key), _sk.iv));
            Program.Write(ve, src, dest, n);
        }

        //----------------------------------------------------------------------------------

        private static void Write 
        (
              BufferedCipherBase bcb
            , int                buffersize
            , Stream             src
            , Stream             dest
            , bool               progressbar = true
        ){
            byte[] i = new byte[buffersize];
            long   l = src.Length;
            long   p = 0;
            int    n;

            while ((n = src.Read(i, 0, i.Length)) > 0)
            {
                byte[] o = bcb.DoFinal(i, 0, n);

                dest.Write(o, 0, o.Length);
                Array.Clear(o, 0, o.Length);

                if (progressbar)
                    Program.Progress(p += n, l, n);
            }

            Array.Clear(i, 0, i.Length);
        }

        //----------------------------------------------------------------------------------

        private static void WriteAndSign
        (
              ISigner            signer
            , BufferedCipherBase bcb
            , int                buffersize
            , Stream             src
            , Stream             dest
        ){
            byte[] i = new byte[buffersize];
            long   l = src.Length;
            long   p = 0;
            int    n;

            while ((n = src.Read(i, 0, i.Length)) > 0)
            {
                byte[] o = bcb.DoFinal(i, 0, n);

                dest.Write(o, 0, o.Length);

                if (_job == CryptoJob.ENCRYPT)
                    signer.BlockUpdate(o, 0, o.Length);

                else signer.BlockUpdate(i, 0, n);

                Array.Clear(o, 0, o.Length);
                Program.Progress(p += n, l, n);
            }

            Array.Clear(i, 0, i.Length);

            if (_job == CryptoJob.ENCRYPT)
                File.WriteAllBytes(_sign, signer.GenerateSignature());

            else Program.VerifySignature(signer);   
        }

        //----------------------------------------------------------------------------------

        private static void VerifySignature (ISigner signer)
        {
            string s = "Signature verification ";

            if (!signer.VerifySignature(File.ReadAllBytes(_sign)))
                throw new Exception(s + "failed!");

            else Messenger.Print
            (
                  Messenger.Icon.INFORMATION
                , s + "success!"
                , false
                , true
            );
        }

        //----------------------------------------------------------------------------------
        private static bool SignatureExists ()
        {
            if (!string.IsNullOrEmpty(_sign))
            {
                if (_job == CryptoJob.ENCRYPT)
                {
                    if (!Program.ValidatePath(_sign))
                        throw new Exception("Invalid signature file!");

                    Program.OverwriteFileCheck(_sign);
                }

                else if (!File.Exists(_sign))
                    throw new Exception("Signature file not found!");

                return true;
            }

            return false;
        }

        //----------------------------------------------------------------------------------

        private static void ValidateKeyPairSize ()
        {
            if (_keysize < 256 || _keysize % 8 != 0)
                throw new Exception(MSG_INVALID_KEY_SIZE);

            else if (_keysize < 768) Program.Question
            (
                  MSG_KEYPAIR_INSECURE + MSG_CONTINUE_QUESTION
                , true
            );

            else if (_keysize > 1024) Program.Question
            (
                  MSG_LARGE_KEYSIZE + MSG_CONTINUE_QUESTION
                , true
            );
        }

        //----------------------------------------------------------------------------------

        private static void AsymmetricKeyPairGen (AsymmetricCipherKeyPair akp)
        {
            byte[] dat, tmp;
            bool   ctl = false;

            if (akp.Public != null)
            {
                ctl = true;
                dat = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(akp.Public).GetDerEncoded();

                if (_format == CryptoFormat.BASE64)
                {
                    tmp = Program.Base64Encode(dat);
                    Array.Clear(dat, 0, dat.Length);
                    dat = tmp;
                }

                else if (_format != CryptoFormat.RAW)
                    throw new Exception(MSG_INVALID_FORMAT);

                File.WriteAllBytes(_public_key, dat);
                Array.Clear(dat, 0, dat.Length);
            }

            if (akp.Private != null)
            {
                ctl = true;
                dat = PrivateKeyInfoFactory.CreatePrivateKeyInfo(akp.Private).GetDerEncoded();

                if (_format == CryptoFormat.BASE64)
                {
                    tmp = Program.Base64Encode(dat);
                    Array.Clear(dat, 0, dat.Length);
                    dat = tmp;
                }

                else if (_format != CryptoFormat.RAW)
                    throw new Exception(MSG_INVALID_FORMAT);

                File.WriteAllBytes(_private_key, dat);
                Array.Clear(dat, 0, dat.Length);
            }

            if (!ctl)
                throw new Exception("No keys found!");
        }

        //----------------------------------------------------------------------------------

        private static AsymmetricKeyParameter ImportAsymmetricKey
        (
              byte[] data
            , bool   publickey
            , string emsg
            , bool   reserved = false
        ){
            Program.TryBase64Decode(ref data);

            try
            {
                if (publickey)
                    return PublicKeyFactory.CreateKey(data);
            }

            catch (Exception) 
            {
                if (reserved)
                    throw new Exception(emsg);

                reserved = true;
            }

            try
            {
                return PrivateKeyFactory.CreateKey(data);
            }

            catch (Exception)
            {
                if (reserved)
                    throw new Exception(emsg);

                return Program.ImportAsymmetricKey(data, true, emsg, true);
            }

            throw new Exception(emsg);
        }

        //----------------------------------------------------------------------------------

        private static AsymmetricKeyParameter ImportAsymmetricKey 
        (
              string file
            , bool   publickey
            , string emsg
        ){
            if (!File.Exists(file))
                throw new Exception(emsg, new Exception(MSG_INNER_EXCEPTION_CTRL));

            
            byte[]                 data = File.ReadAllBytes(file);
            AsymmetricKeyParameter akp  = Program.ImportAsymmetricKey(data, publickey, emsg);

            Array.Clear(data, 0, data.Length);
            return akp;
        }

        //----------------------------------------------------------------------------------

        private static AsymmetricCipherKeyPair ElGamalKeyPairGen 
        (
              bool                        save = true
            , ElGamalPublicKeyParameters  pbk  = null
            , ElGamalPrivateKeyParameters pvk  = null

        ){
            AsymmetricCipherKeyPair akp = null;

            if (pbk != null || pvk != null)
            {
                Program.ValidateKeyPairFiles(pbk != null, pvk != null);
                akp = new AsymmetricCipherKeyPair(pbk, pvk);
            }

            else
            {
                if (save)
                    Program.ValidateKeyPairFiles();

                Program.ValidateKeyPairSize();

                ElGamalKeyPairGenerator    kpg = new ElGamalKeyPairGenerator();
                ElGamalParametersGenerator epg = new ElGamalParametersGenerator();

                epg.Init(_keysize, Program.GetPrimeCertainty(_keysize, 256), new SecureRandom());
                kpg.Init
                (
                    new ElGamalKeyGenerationParameters
                    (
                          new SecureRandom()
                        , epg.GenerateParameters()
                    )
                );

                akp = kpg.GenerateKeyPair();
            }

            if (save)
                Program.AsymmetricKeyPairGen(akp);

            return akp;
        }

        //----------------------------------------------------------------------------------

        private static void CryptoElGamal
        (
              bool                 encryption
            , ElGamalKeyParameters key
            , Stream               src
            , Stream               dest
            , bool                 signature   = false
            , bool                 progressbar = true
        ){
            IAsymmetricBlockCipher abc;

            if (_padding == CryptoPadding.OAEP)
                abc = Program.GetOaepEncoding(new ElGamalEngine(), key.Parameters.P.BitLength);

            else if (_padding == CryptoPadding.PKCS1)
                abc = new Pkcs1Encoding(new ElGamalEngine());

            else throw new Exception(MSG_INVALID_PADDING_MODE);

            BufferedAsymmetricBlockCipher bac = new BufferedAsymmetricBlockCipher(abc);
            bac.Init(encryption, key);

            if (!signature)
                Program.Write(bac, bac.GetBlockSize(), src, dest, progressbar);

            else
            {
                ModGenericSigner signer = new ModGenericSigner
                (
                      new Pkcs1Encoding(new ElGamalEngine())
                    , Program.GetBouncyCastleDigest(key.Parameters.P.BitLength)
                );

                signer.Init(encryption, key);
                Program.WriteAndSign(signer, bac, bac.GetBlockSize(), src, dest);
            }
        }

        //----------------------------------------------------------------------------------

        private static byte[] CryptoElGamal (ElGamalKeyParameters key, byte[] data)
        {
            byte[]        b;
            CryptoPadding p = _padding;
            string        h = _hash;

            _padding = key.Parameters.P.BitLength < 344 ? CryptoPadding.PKCS1 : CryptoPadding.OAEP;
            _hash    = HASH_SHA1;

            using (MemoryStream dt = new MemoryStream(data))
            {
                using (MemoryStream bf = new MemoryStream())
                {
                    Program.CryptoElGamal(_job == CryptoJob.ENCRYPT, key, dt, bf, false, false);
                    b = bf.ToArray();
                }
            }

            _padding = p;
            _hash    = h;

            return b;
        }

        //----------------------------------------------------------------------------------

        private static byte[] GetNaccacheSternKeyCommonBytes (NaccacheSternKeyParameters key)
        {
            byte[] b, a = null;

            using (MemoryStream ms = new MemoryStream())
            {
                b = BitConverter.GetBytes(key.IsPrivate);
                ms.Write(b, 0, b.Length);
                Array.Clear(b, 0, b.Length);

                b = Program.GetBytes(key.LowerSigmaBound);
                ms.Write(b, 0, b.Length);
                Array.Clear(b, 0, b.Length);

                a = key.G.ToByteArray();
                b = Program.GetBytes(a.Length);
                ms.Write(b, 0, b.Length);
                ms.Write(a, 0, a.Length);
                Array.Clear(b, 0, b.Length);
                Array.Clear(a, 0, a.Length);

                a = key.Modulus.ToByteArray();
                b = Program.GetBytes(a.Length);
                ms.Write(b, 0, b.Length);
                ms.Write(a, 0, a.Length);
                Array.Clear(b, 0, b.Length);
                Array.Clear(a, 0, a.Length);

                a = ms.ToArray();
            }

            return a;
        }

        //----------------------------------------------------------------------------------

        private static void NaccacheSternKeyPairGen ()
        {
            Program.ValidateKeyPairSize();
            Program.ValidateKeyPairFiles();

            NaccacheSternKeyPairGenerator        kpg = new NaccacheSternKeyPairGenerator();
            NaccacheSternKeyGenerationParameters kgp = new NaccacheSternKeyGenerationParameters
            (
                  new SecureRandom()
                , _keysize
                , Program.GetPrimeCertainty(_keysize, 256)
                , _small_primes
            );

            kpg.Init(kgp);

            AsymmetricCipherKeyPair           akp = kpg.GenerateKeyPair();
            NaccacheSternKeyParameters        pbk = (NaccacheSternKeyParameters)akp.Public;
            NaccacheSternPrivateKeyParameters pvk = (NaccacheSternPrivateKeyParameters)akp.Private;

            int    l;
            byte[] a, b;

            a = Program.GetNaccacheSternKeyCommonBytes(pbk);

            if (_format == CryptoFormat.BASE64)
            {
                b = Program.Base64Encode(a);
                Array.Clear(a, 0, a.Length);
                a = b;
            }

            File.WriteAllBytes(_public_key, a);
            Array.Clear(a, 0, a.Length);

            using (MemoryStream ms = new MemoryStream())
            {
                a = Program.GetNaccacheSternKeyCommonBytes(pvk);
                ms.Write(a, 0, a.Length);
                Array.Clear(a, 0, a.Length);

                a = pvk.PhiN.ToByteArray();
                b = Program.GetBytes(a.Length);
                ms.Write(b, 0, b.Length);
                ms.Write(a, 0, a.Length);
                Array.Clear(b, 0, b.Length);
                Array.Clear(a, 0, a.Length);

                b = Program.GetBytes(l = pvk.SmallPrimesList.Count);
                ms.Write(b, 0, b.Length);
                Array.Clear(b, 0, b.Length);

                for (int i = 0; i < l; ++i)
                {
                    a = ((BigInteger)pvk.SmallPrimesList[i]).ToByteArray();
                    b = Program.GetBytes(a.Length);
                    ms.Write(b, 0, b.Length);
                    ms.Write(a, 0, a.Length);
                    Array.Clear(b, 0, b.Length);
                    Array.Clear(a, 0, a.Length);
                }

                a = ms.ToArray();
            }

            if (_format == CryptoFormat.BASE64)
            {
                b = Program.Base64Encode(a);
                Array.Clear(a, 0, a.Length);
                a = b;
            }

            File.WriteAllBytes(_private_key, a);
            Array.Clear(a, 0, a.Length);
        }

        //----------------------------------------------------------------------------------

        private static NaccacheSternKeyParameters NaccacheSternImportKey
        (
              string path
            , bool   publickey
        ){
            string e = publickey ? MSG_INVALID_PUBLIC_KEY : MSG_INVALID_PRIVATE_KEY;
            
            if (!File.Exists(path))
                throw new Exception(e, new Exception(MSG_INNER_EXCEPTION_CTRL));

            byte[]                     d = File.ReadAllBytes(path);
            NaccacheSternKeyParameters k = Program.NaccacheSternImportKey(d, publickey, e);
            
            Array.Clear(d, 0, d.Length);
            return k;
        }

        //----------------------------------------------------------------------------------

        private static NaccacheSternKeyParameters NaccacheSternImportKey
        (
              byte[] data
            , bool   publickey
            , string emsg
        ){
            Program.TryBase64Decode(ref data);

            int x = data.Length;

            if (x < 78)
                throw new Exception(emsg);

            byte[]           a;
            byte[]           n = new byte[4];
            int              c = 0;
            int              l = 0;
            BigInteger       g = null;
            BigInteger       m = null;
            BigInteger       p = null;
            bool             b = false;
            List<BigInteger> s = null;

            using (MemoryStream ms = new MemoryStream(data))
            {
                b = BitConverter.ToBoolean(new byte[1] { (byte)ms.ReadByte() }, 0);

                if (!publickey && !b || ms.Read(n, 0, 4) < 4)
                    throw new Exception(emsg);

                x -= 5;
                if ((c = Program.ToInt32(n)) < 0)
                    throw new Exception(emsg);

                if (ms.Read(n, 0, 4) < 4 || (l = Program.ToInt32(n)) > (x -= 4) || l < 0)
                    throw new Exception(emsg);

                a  = new byte[l];
                if (ms.Read(a, 0, l) < l)
                    throw new Exception(emsg);

                x -= l;
                g = new BigInteger(a);
                Array.Clear(a, 0, l);

                if (ms.Read(n, 0, 4) < 4 || (l = Program.ToInt32(n)) > (x -= 4) || l < 0)
                    throw new Exception(emsg);

                x -= l;
                a = new byte[l];
                if (ms.Read(a, 0, l) < l)
                    throw new Exception(emsg);

                m = new BigInteger(a);
                Array.Clear(a, 0, l);

                if (!publickey)
                {
                    if (ms.Read(n, 0, 4) < 4 || (l = Program.ToInt32(n)) > (x -= 4) || l < 0)
                        throw new Exception(emsg);

                    x -= l; 
                    a  = new byte[l];
                    if (ms.Read(a, 0, l) < l)
                        throw new Exception(emsg);

                    p = new BigInteger(a);
                    Array.Clear(a, 0, l);

                    if (ms.Read(n, 0, 4) < 4 || (l = Program.ToInt32(n)) > (x -= 4) || l < 0)
                        throw new Exception(emsg);
                    
                    s = new List<BigInteger>(l);
                    for (int i = 0, t; i < l; ++i)
                    {
                        if (ms.Read(n, 0, 4) < 4 || (t = Program.ToInt32(n)) > (x -= 4) || t < 0)
                            throw new Exception(emsg);

                        x -= t; 
                        a  = new byte[t];
                        if (ms.Read(a, 0, t) < t)
                            throw new Exception(emsg);

                        s.Add(new BigInteger(a));
                        Array.Clear(a, 0, t);
                    }
                }
            }

            if (publickey && b)
            {
                b = false;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , "A public key was requested and the key provided is private!"
                    , false
                    , true
                );
            }

            return publickey ? new NaccacheSternKeyParameters(b, g, m, c) :
                   new NaccacheSternPrivateKeyParameters(g, m, c, s, p);
        }

        //----------------------------------------------------------------------------------

        private static void CryptoNaccacheStern
        (
              bool                       encryption
            , NaccacheSternKeyParameters key
            , Stream                     src
            , Stream                     dest
            , bool                       signature   = false
            , bool                       progressbar = true
            
        ){
            BufferedAsymmetricBlockCipher bac = new BufferedAsymmetricBlockCipher
            (
                new Pkcs1Encoding(new NaccacheSternEngine())
            );

            bac.Init(encryption, key);

            if (!signature)
                Program.Write(bac, bac.GetBlockSize(), src, dest, progressbar);

            else
            {
                ModGenericSigner signer = new ModGenericSigner
                (
                        new Pkcs1Encoding(new NaccacheSternEngine())
                      , Program.GetBouncyCastleDigest(key.Modulus.BitLength)
                );
                
                signer.Init(encryption, key);
                Program.WriteAndSign(signer, bac, bac.GetBlockSize(), src, dest);
            }
        }

        //----------------------------------------------------------------------------------

        private static byte[] CryptoNaccacheStern (NaccacheSternKeyParameters key, byte[] data)
        {
            byte[] b;

            using (MemoryStream dt = new MemoryStream(data))
            {
                using (MemoryStream bf = new MemoryStream())
                {
                    Program.CryptoNaccacheStern(_job == CryptoJob.ENCRYPT, key, dt, bf, false, false);
                    b = bf.ToArray();
                }
            }

            return b;
        }

        //----------------------------------------------------------------------------------

        private static void IesKeyPairGen ()
        {
            AsymmetricCipherKeyPair akp;

            if (_mode == ECIES)
                akp = Program.GetCurveKeyPair(ECDH);
            
            else
            {
                if (_keysize == -1)
                    _keysize = 256;

                Program.ValidateKeyPairSize();

                DHKeyPairGenerator    kpg = new DHKeyPairGenerator();
                DHParametersGenerator dpg = new DHParametersGenerator();

                dpg.Init(_keysize, Program.GetPrimeCertainty(_keysize), new SecureRandom());
                
                DHKeyGenerationParameters kgp = new DHKeyGenerationParameters
                (
                      new SecureRandom()
                    , dpg.GenerateParameters()
                );

                kpg.Init(kgp);
                akp = kpg.GenerateKeyPair(); 
            }

            Program.AsymmetricKeyPairGen(akp);
        }

        //----------------------------------------------------------------------------------

        private static void IesImportKeys (ref ICipherParameters pbk, ref ICipherParameters pvk)
        {
            pbk = Program.ImportAsymmetricKey
            (
                  _public_key
                , true
                , MSG_INVALID_PUBLIC_KEY
            );

            pvk = Program.ImportAsymmetricKey
            (
                  _private_key
                , false
                , MSG_INVALID_PRIVATE_KEY
            );
        }


        //----------------------------------------------------------------------------------

        private static void CryptoIes
        (
              bool    encryption
            , IDigest digest
            , Stream  src
            , Stream  dest
        ){
            IBasicAgreement   iba = null;
            IBlockCipher      ibc = null;
            ICipherParameters pbk = null;
            ICipherParameters pvk = null;
            IesEngine         ie  = null;
            int               bsz = _buffersize;

            Program.IesImportKeys(ref pbk, ref pvk);

            switch (_mode)
            {
                case ECIES:        
                    iba = new ECDHCBasicAgreement();
                    break;

                case DLIES:
                    iba = new DHBasicAgreement();
                    break;
            }

            switch (_ies_cipher)
            {
                case THREEFISH:
                    ibc = new ThreefishEngine(_keysize);
                    break;

                case RIJNDAEL:
                    ibc = new RijndaelEngine(_blocksize);
                    break;

                case AES:
                    ibc = new AesEngine();
                    break;

                case DES:
                    ibc = new DesEngine();
                    break;

                case TDES:
                    ibc = new DesEdeEngine();
                    break;

                case RC2:
                    ibc = new RC2Engine();
                    break;

                case RC5:
                    ibc = _rc5b64 ? (IBlockCipher)new RC564Engine() : new RC532Engine();
                    break;

                case RC6:
                    ibc = new RC6Engine();
                    break;

                case CAMELLIA:
                    ibc = new CamelliaEngine();
                    break;

                case SKIPJACK:
                    ibc = new SkipjackEngine();
                    break;

                case GOST:
                    ibc = new Gost28147Engine();
                    break;

                case TWOFISH:
                    ibc = new TwofishEngine();
                    break;

                case TNEPRES:
                    ibc = new TnepresEngine();
                    break;

                case BLOWFISH:
                    ibc = new BlowfishEngine();
                    break;

                case SERPENT:
                    ibc = new SerpentEngine();
                    break;

                case CAST5:
                    ibc = new Cast5Engine();
                    break;

                case CAST6:
                    ibc = new Cast6Engine();
                    break;

                case IDEA:
                    ibc = new IdeaEngine();
                    break;

                case NOEKEON:
                    ibc = new NoekeonEngine();
                    break;

                case SEED:
                    ibc = new SeedEngine();
                    break;

                case TEA:
                    ibc = new TeaEngine();
                    break;

                case XTEA:
                    ibc = new XteaEngine();
                    break;

                default:
                    if (!string.IsNullOrEmpty(_ies_cipher))
                        throw new Exception(MSG_INVALID_IES_CIPHER);

                    break;
            }

            if (ibc != null) ie = new IesEngine
            (
                  iba
                , new Kdf2BytesGenerator(digest)
                , new HMac(digest)
                , new PaddedBufferedBlockCipher
                  (
                        Program.GetBlockCipherMode(ibc)
                      , Program.GetBouncyCastlePadding()
                  )
            );

            else ie = new IesEngine
            (
                  iba
                , new Kdf2BytesGenerator(digest)
                , new HMac(digest)
            );

            BufferedIesCipher bic = new BufferedIesCipher(ie);

            bic.Init
            (
                  encryption
                , pvk
                , pbk
                , ibc == null ? new IesParameters(_sk.key, _sk.iv, _keysize) :
                  new IesWithCipherParameters(_sk.key, _sk.iv, digest.GetDigestSize() * 8, _keysize)
            );

            if (!encryption)
            {
                bsz += digest.GetDigestSize();

                if (ibc != null)
                    bsz += ibc.GetBlockSize();
            }

            Program.Write(bic, bsz, src, dest);
        }

        //----------------------------------------------------------------------------------

        private static IDigest GetBouncyCastleDigest ()
        {
            switch (_hash)
            {
                case HASH_KECCAK224:
                    return new KeccakDigest(224);

                case HASH_KECCAK256:
                    return new KeccakDigest(256);

                case HASH_KECCAK384:
                    return new KeccakDigest(384);

                case HASH_KECCAK512:
                    return new KeccakDigest(512);

                case HASH_RIPEMD128:
                    return new RipeMD128Digest();

                case HASH_RIPEMD160:
                    return new RipeMD160Digest();

                case HASH_RIPEMD256:
                    return new RipeMD256Digest();

                case HASH_RIPEMD320:
                    return new RipeMD320Digest();

                case HASH_SHA1:
                    return new Sha1Digest();

                case HASH_SHA224:
                    return new Sha224Digest();

                case HASH_SHA256:
                    return new Sha256Digest();

                case HASH_SHA384:
                    return new Sha384Digest();

                case HASH_SHA512:
                    return new Sha512Digest();

                case HASH_MD2:
                    return new MD2Digest();

                case HASH_MD4:
                    return new MD4Digest();

                case HASH_MD5:
                    return new MD5Digest();

                case HASH_SKEIN256:
                    return new SkeinDigest(256, 32);

                case HASH_SKEIN512:
                    return new SkeinDigest(512, 64);

                case HASH_WHIRLPOOL:
                    return new WhirlpoolDigest();

                default:
                    throw new Exception(MSG_INVALID_HASH);
            }
        }

        //----------------------------------------------------------------------------------

        private static string ComputeHashFromStream (HashAlgorithm hash, Stream stream)
        {
            hash.Initialize();

            byte[]        b = hash.ComputeHash(stream);
            StringBuilder s = new StringBuilder();

            for (int i = 0, l = b.Length; i < l; ++i)
            {
                s.Append(b[i].ToString("x2"));
                b[i] = 0;
            }

            return s.ToString();
        }

        //----------------------------------------------------------------------------------

        private static string Checksum (Stream s)
        {
            HashAlgorithm h;

            switch (_hash)
            {
                case HASH_ADLER32:
                    h = new HashAlgorithmWrapper(new Adler32());
                    break;

                case HASH_CRC32_IEEE:
                    h = new HashAlgorithmWrapper(new CRC32_IEEE());
                    break;

                case HASH_CRC32_CASTAGNOLI:
                    h = new HashAlgorithmWrapper(new CRC32_CASTAGNOLI());
                    break;

                case HASH_CRC32_KOOPMAN:
                    h = new HashAlgorithmWrapper(new CRC32_KOOPMAN());
                    break;

                case HASH_CRC32_Q:
                    h = new HashAlgorithmWrapper(new CRC32_Q());
                    break;

                case HASH_CRC64_ISO:
                    h = new HashAlgorithmWrapper(new CRC64_ISO());
                    break;

                case HASH_CRC64_ECMA:
                    h = new HashAlgorithmWrapper(new CRC64_ECMA());
                    break;

                default:
                    throw new Exception(MSG_INVALID_HASH);
            }

            return Program.ComputeHashFromStream(h, s);
        }

        //----------------------------------------------------------------------------------

        private static string GetRandomString (int length)
        {
            if (length < 1)
                throw new ArgumentOutOfRangeException("length");

            StringBuilder sb = new StringBuilder();
            byte[]        br = Program.GetRandomBytes(length);
            string        cp = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv" +
                               "wxyz0123456789!#%&()*+-,./:;<>?@[]^_{|}~";

            length = cp.Length - 1;

            foreach (byte b in br)
                sb.Append(cp[b % length]);

            Array.Clear(br, 0, br.Length);
            return sb.ToString();
        }

        //----------------------------------------------------------------------------------

        private static void RandomGen (string target)
        {
            string sf = "\r\"";
            Random rd = new Random();
                        
			if (string.IsNullOrEmpty(_password))
			{
            	Messenger.Print
            	(
            		  Messenger.Icon.INFORMATION
                    , "Random Password for " + target + " -> \""
            	);
            	
            	Messenger.Print
            	(
                      (_password = Program.GetRandomString(rd.Next(8, 20))) + sf
               		, new ConsoleColor[] { ConsoleColor.DarkYellow, ConsoleColor.Gray }
				);
			}

            if (!_saltleaking && string.IsNullOrEmpty(_salt))
			{
	            Messenger.Print
	            (
	            	  Messenger.Icon.INFORMATION
                    , "Random Salt for " + target + " -> \""
	           	);
	           	
	            Messenger.Print
	            (
	                  (_salt = Program.GetRandomString(8)) + sf
	                , new ConsoleColor[] { ConsoleColor.DarkYellow, ConsoleColor.Gray }
	            );
	        }
        }

        //----------------------------------------------------------------------------------

        private static void DefinePassword (bool asymmetric = false)
        {
            bool   b = false;
            string s = "The password does not match!";
            _haspwd  = false;

            if (string.IsNullOrEmpty(_password)) do
            {
                if (b && !Program.Question(s + "\n\n> Do you want to repeat the password entry?", false))
                {
                    if (!_raise)
                        _password = string.Empty;

                    throw new Exception(s);
                }

                _password = Program.Prompt
                (
                      asymmetric ? MSG_PRIVATE_KEY_PWD : MSG_PASSWORD
                    , true
                );
            }
            while (b = _password != Program.Prompt(MSG_CONFIRM_PWD, true));

            if (!asymmetric && !_saltleaking && string.IsNullOrEmpty(_salt))
            {
                _salt        = Program.Prompt(MSG_SALT, false, 8, true);
                _saltleaking = true;
            }

            _haspwd = true;
        }

        //----------------------------------------------------------------------------------

        private static void ProvideKey (string target, int nfiles, bool hightdiv = false)
        {
            if (!string.IsNullOrEmpty(_key))
                Program.SetSymmetricKey(_keysize, _blocksize, hightdiv);

            else
            {
                if (!_random || _job == CryptoJob.DECRYPT)
                    Program.DefinePassword();

                else
                {
                    Program.RandomGen
                    (
                          !_tellapart && nfiles > 1 ? nfiles + FILES : '"' +
                          Path.GetFileName(target) + '"'
                    );

                    if (!_tellapart)
                        _random = false;
                }

                Program.KeyGen(_keysize, _blocksize, hightdiv);

                if (_tellapart)
                {
                    _key         = string.Empty;
                    _iv          = string.Empty;
                    _password    = string.Empty;
                    _salt        = string.Empty;
                    _saltleaking = false;
                }
            }
        }

        //----------------------------------------------------------------------------------

        private static void ValidateParams (ulong ul1, ulong ul2, ulong ul3 = 0)
        {
            bool b;

            if ((ul1 & 0x1) == 0x1 && !_rfc4648)
            {
                _rfc4648 = true;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "no-rfc4648")
                    , false
                    , true
                );
            }
            
            if ((ul1 & 0x10) == 0x10 && _b32hex)
            {
                _b32hex = false;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "b32-hex")
                    , false
                    , true
                );
            }
            
            if ((ul1 & 0x100) == 0x100 && _code != CODE)
            {
                _code = CODE;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "base-code")
                    , false
                    , true
                );
            }
            
            if (((ul1 & 0x1000) == 0x1000 || _job != CryptoJob.ENCRYPT) && _charsperline != 0)
            {
                _charsperline = 0;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "base-line-wrap")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x10000) == 0x10000 && _rounds != 20)
            {
                _rounds = 20;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "rounds")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x100000) == 0x100000 && _rc5b64)
            {
                _rc5b64 = false;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "rc5-64b")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x1000000) == 0x1000000 && _ksa3)
            {
                _ksa3 = false;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "vmpc-ksa3")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x10000000) == 0x10000000 && _buffersize != 1024)
            {
                _buffersize = 1024;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "max-buffer-size")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x100000000) == 0x100000000 && !string.IsNullOrEmpty(_key))
            {
                _key = string.Empty;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "key")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x1000000000) == 0x1000000000 && !string.IsNullOrEmpty(_iv))
            {
                _iv = string.Empty;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "initial-vector")
                    , false
                    , true
                );
            }
                     
            if ((ul1 & 0x10000000000) == 0x10000000000 && !string.IsNullOrEmpty(_password))
            {
                _password = string.Empty;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "password")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x100000000000) == 0x100000000000 && !string.IsNullOrEmpty(_salt))
            {
                _salt = string.Empty;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "salt")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x1000000000000) == 0x1000000000000 && _hash != HASH_SHA512)
            {
                _hash = HASH_SHA512;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "hash")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x10000000000000) == 0x10000000000000 && _iterations != 1000)
            {
                _iterations = 1000;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "iterations")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x100000000000000) == 0x100000000000000 && _ciphermode != CipherMode.CBC)
            {
                _ciphermode = CipherMode.CBC;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "cipher-mode")
                    , false
                    , true
                );
            }

            if ((ul1 & 0x1000000000000000) == 0x1000000000000000 && _padding != CryptoPadding.PKCS7)
            {
                _padding = CryptoPadding.PKCS7;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "padding")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x1) == 0x1 && _random)
            {
                _random = false;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "random-gen")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x10) == 0x10 && _blocksize != -1)
            {
                _blocksize = -1;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "block-size")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x100) == 0x100 && _feedbacksize != -1)
            {
                _feedbacksize = -1;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "feedback-size")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x1000) == 0x1000 && _keysize != -1)
            {
                _keysize = -1;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "key-size")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x10000) == 0x10000)
            {
                if (!string.IsNullOrEmpty(_public_key))
                {
                    _public_key = string.Empty;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "public-key")
                        , false
                        , true
                    );
                }

                if (!string.IsNullOrEmpty(_private_key))
                {
                    _private_key = string.Empty;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "private-key")
                        , false
                        , true
                    );
                }
            }

            if ((ul2 & 0x100000) == 0x100000 && _cer.Count > 0)
            {
                _cer.Clear();
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "x509-file or x509-store")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x1000000) == 0x1000000 && _format != CryptoFormat.RAW)
            {
                _format = CryptoFormat.RAW;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "format")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x10000000) == 0x10000000 && _padding == CryptoPadding.OAEP)
            {
                _padding = CryptoPadding.PKCS7;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "oaep")
                    , false
                    , true
                );
            }

            if ((b = (ul2 & 0x100000000) == 0x100000000) || _job == CryptoJob.DECRYPT)
            {
                if (b && _ska != SymmetricKeyAlgorithmTag.Aes256)
                {
                    _ska = SymmetricKeyAlgorithmTag.Aes256;
                    Messenger.Print
                    (
                            Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "pgp-cipher")
                        , false
                        , true
                    );
                }

                if (_cat != CompressionAlgorithmTag.Zip)
                {
                    _cat = CompressionAlgorithmTag.Zip;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "pgp-compress")
                        , false
                        , true
                    );
                }
            }

            if ((ul2 & 0x1000000000) == 0x1000000000 || (!_generator && !_export))
            {
                if (!string.IsNullOrEmpty(_pgp_id))
                {
                    _pgp_id = string.Empty;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "pgp-id")
                        , false
                        , true
                    );
                }

                if (_sha1)
                {
                    _sha1 = false;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "pgp-sha1")
                        , false
                        , true
                    );
                }

                if (_pgp_master != RSA)
                {
                    _pgp_master = RSA;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "pgp-master")
                        , false
                        , true
                    );
                }
            }

            if ((ul2 & 0x10000000000) == 0x10000000000 && _crossbreeding)
            {
                _crossbreeding = false;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "crossbreeding")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x100000000000) == 0x100000000000 && !string.IsNullOrEmpty(_sbox))
            {
                _sbox = string.Empty;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "gost-box")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x1000000000000) == 0x1000000000000 && _ies_cipher != AES)
            {
                _ies_cipher = AES;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "ies-cipher")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x10000000000000) == 0x10000000000000)
            {
                if (_curve.Count > 0)
                {
                    _curve.Clear();
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "curve")
                        , false
                        , true
                    );
                }

                if (!string.IsNullOrEmpty(_curvestore))
                {
                    _curvestore = string.Empty;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "curve-store")
                        , false
                        , true
                    );
                }
            }

            if ((ul2 & 0x100000000000000) == 0x100000000000000 && _without_iv)
            {
                _without_iv = false;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "without-iv-tweak")
                    , false
                    , true
                );
            }

            if ((ul2 & 0x1000000000000000) == 0x1000000000000000 && _rsa_bc)
            {
                _rsa_bc = false;
                Messenger.Print
                (
                      Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, RSA_BC)
                    , false
                    , true
                );
            }

            if (_generator)
            {
                if ((ul3 & 0x1) == 0x1)
                {
                    _generator = false;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "key-pair-gen")
                        , false
                        , true
                    );
                }

                if ((ul3 & 0x10) == 0x10)
                    throw new Exception(MSG_GEN_WITH_ENCRYPT);

            }

            if ((ul3 & 0x100) == 0x100 || _job == CryptoJob.OTHER)
            {
                if (_pgp_sign)
                {
                    _pgp_sign = false;
                    Messenger.Print
                    (
                          Messenger.Icon.WARNING
                        , string.Format(MSG_GENERIC_USE, "pgp-sign")
                        , false
                        , true
                    );
                }
            }


            if ((ul3 & 0x1000) == 0x1000 && _pgp_algorithm != RSA)
            {
                _pgp_algorithm = RSA;
                Messenger.Print
                (
                        Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "pgp-algorithm")
                    , false
                    , true
                );
            }

            if ((ul3 & 0x10000) == 0x10000 && _public_exponent != 0)
            {
                _public_exponent = 0;
                Messenger.Print
                (
                        Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "public-exponent")
                    , false
                    , true
                );
            }


            if ((ul3 & 0x100000) == 0x100000 && _certainty != 0)
            {
                _certainty = 0;
                Messenger.Print
                (
                        Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "certainty")
                    , false
                    , true
                );
            }

            if ((ul3 & 0x1000000) == 0x100000 && !string.IsNullOrEmpty(_sign))
            {
                _sign = string.Empty;
                Messenger.Print
                (
                        Messenger.Icon.WARNING
                    , string.Format(MSG_GENERIC_USE, "sign")
                    , false
                    , true
                );
            }
        }

        //----------------------------------------------------------------------------------

        private static bool ValidatePath (string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            char[] chrs = Path.GetInvalidPathChars();
            
            foreach (char c in chrs)
                if (path.IndexOf(c) != -1)
                    return false;

            if (!Directory.Exists(Path.GetDirectoryName(Path.GetFullPath(path))))
                return false;

            return true;
        }

        //----------------------------------------------------------------------------------

        private static bool Question 
        (
              string         msg
            , bool           exit = false
            , Messenger.Icon icon = Messenger.Icon.QUESTION
        ){
            bool b = ConsoleKey.Y == Messenger.Print
            (
                  icon
                , msg
                , new ConsoleKey[] { ConsoleKey.Y, ConsoleKey.N }
                , true
                , true
            );

            if (!b && exit)
            {
                Messenger.Print(Messenger.Icon.WARNING, MSG_PROCESS_CANCELLED);
                Environment.Exit(0);
            }

            return b;
        }

        //----------------------------------------------------------------------------------

        private static bool OverwriteFileCheck (string file, bool overwrite = false)
        {
            if (File.Exists(file) && !overwrite)
            {
                overwrite = Program.Question
                (
                    String.Format
                    (
                          "The file \"{0}\" already exists!\n\n> Do you want to overwrite?"
                        , Path.GetFullPath(file)
                    )
                    , true
                );
            }

            return true;
        }

        //----------------------------------------------------------------------------------

        private static void ExceptionControl (int id)
        {
            if (_e_num != id)
            {
                _e_num = id;
                _e_cnt = 1;
            }

            else if (++_e_cnt > _e_max)
            {
                Program.Question
                (
                      string.Format(MSG_EXCEPTION_LOOPING, _e_max) +
                      MSG_CONTINUE_QUESTION
                    , true
                );

                _e_num = 0;
            }
        }

        //----------------------------------------------------------------------------------

        private static void MoveFile (string src, string dest)
        {
            if (File.Exists(src))
            {
                bool b = File.Exists(dest);

                Messenger.Print
                (
                      Messenger.Icon.INFORMATION
                    , string.Format
                      (
                            "{0} the file \"{1}\" {2} \"{3}\""
                          , b ? "Overwriting" : "Moving"
                          , Path.GetFileName(dest)
                          , b ? "in" : "to"
                          , Path.GetDirectoryName(dest)
                      )
                    , false
                    , true
                );

                using (FileStream fsr = File.OpenRead(src))
                    using (FileStream fsw = File.Create(dest))
                        Program.Write(fsr, fsw, fsr.Length);

                File.Delete(src);
            }
        }

        //----------------------------------------------------------------------------------

        private static void ShowBanner ()
        {
            if (_banner)
            {
                Version v = Assembly.GetExecutingAssembly().GetName().Version;

                Messenger.Print
                (
                      "\n Crypto Tool v." + v.Major + "." + v.Minor + "." + v.Build + "." +
                      v.Revision + " Created in 2018 by José A. Rojo L.\n"
                    , ConsoleColor.DarkGreen
                );

                _banner = false;
            }
        }

        //----------------------------------------------------------------------------------

        private static void ShowHelp ()
        {
            Program.ShowBanner();
            Messenger.Print
            (
                  "\n {f:14}Usage:\n\n\t{f:7}crypto [options...] input-file-name\n"                       +
                  "\n {f:14}Options:\n\n"                                                                 +
                  "{f:15}\t-m  --mode\t    {t:30,f:7}Algorithm mode. Use the combined help with this "    +
                  "modifier to list or for more info.{t:0,f:15}\n"                                        +
                  "\t-e  --encrypt-encode  {t:30,f:7}Encrypt or encode operation indicator."              +
                  "{t:0,f:15}\n\t-d  --decrypt-decode  {t:30,f:7}Decrypt or decode operation indicator."  +
                  "{t:0,f:15}\n\t-2  --b32-hex         {t:30,f:7}For B32 mode. Uses The extended hex "    +
                  "alphabet.{t:0,f:15}\n\t-8  --no-rfc4648      {t:30,f:7}For B32 and B64 modes. Coding"  +
                  " without the RFC4648 specification.{t:0,f:15}\n"                                       +
                  "\t-1  --base-code       {t:30,f:7}Custom characters to be coding in BaseN without "    +
                  "RFC4648 specification. The length must be equal to or greater than the specified base" +
                  " number.{t:0,f:15}\n"                                                                  +
                  "\t-6  --base-line-wrap  {t:30,f:7}Number of characters to adjust the lines for BaseN"  +
                  " mode. The value must be in increments of 8 characters with B2, 6 characters with "    +
                  "B3, 4 characters from B4 to B6 (or B64 with RFC4648), 3 characters from B7 to B15, "   +
                  "and 2 characters from B16 to B64 (without RFC4648). The maximum value is 252 for B3,"  +
                  " 255 from B7 to B15, and 256 for all others.{t:0,f:15}\n"                              +
                  "\t-5  --rounds\t  {t:30,f:7}For RC5, SALSA20, and CHACHA the number of rounds should " +
                  "be a integer value (20 by default).{t:0,f:15}\n"                                       +
                  "\t-4  --rc5-64b\t {t:30,f:7}For RC5 mode. Uses a 64 bits word.{t:0,f:15}\n"            +
                  "\t-3  --vmpc-ksa3       {t:30,f:7}For VMPC mode. Uses the Key Scheduling Algorithm."   +
                  "{t:0,f:15}\n\t-x  --max-buffer-size {t:30,f:7}Maximum buffer size in bytes for read "  +
                  "and write. Modes: All symmetric ciphers and PGP. The default value is 1024."           +
                  "{t:0,f:15}\n\t-k  --key\t     {t:30,f:7}The key characters must have a key size "      +
                  "length divided by 8. It must be accompanied by the initial vector in the "             +
                  "terms subject to that modifier. This option is prioritized over hash, password, salt"  + 
                  ", and iterations. Modes: All symmetric ciphers. This modifier supports "               +
                  "hexadecimal byte notation by the escape characters \\x (two-digit) and \\u for"        +
                  " Unicode (four-digit).{t:0,f:15}\n"                                                    +
                  "\t-i  --initial-vector  {t:30,f:7}Needs to be 16 characters for AES, 3DES, DES, RC2, " +
                  "3FISH, and MARS. SALSA20 requires exactly 8 characters. The RIJNDAEL long must be "    +
                  "equal to the block size divided by 8. With VMPC the value should be between 1 and 768" +
                  " depending on the block size. This modifier supports hexadecimal byte notation by the" +
                  "  escape characters \\x (two-digit) and \\u for Unicode (four-digit)."                 + 
                  "{t:0,f:15}\n"                                                                          +
                  "\t-p  --password\t{t:30,f:7}Word, phrase or file. Modes: All symmetric ciphers  and "  +
                  "PGP private key or x509 certificates (*.pfx or *.pem). This modifier supports "        +
                  "hexadecimal byte notation by the escape characters \\x (two-digit) and \\u for"        +
                  " Unicode (four-digit) with symmetric ciphers.{t:0,f:15}\n"                             +
                  "\t-s  --salt\t    {t:30,f:7}At least 8 characters. Modes: All symmetric ciphers."      +
                  "{t:0,f:15}\n"                                                                          +
                  "\t-h  --hash\t    {t:30,f:7}Hash algorithm. Modes: DIGEST, CHECKSUM, all symmetric "   +
                  " ciphers, ECIES, DLIES, and ELGAMAL or RSA with OAEP (Bouncy Castle). Use  the help "  +
                  "combined with this modifier to list or for more info.{t:0,f:15}\n"                     +
                  "\t-t  --iterations      {t:30,f:7}Number of iterations to do. Range from 1 to "        +
                  "2,147,483,647 (1000 by default). Bear in mind that a greater number of iterations "    +
                  "implies a slower process. Modes: All symmetric ciphers.{t:0,f:15}\n"                   +
                  "\t-c  --cipher-mode     {t:30,f:7}CBC (Cipher Block Chianing) by default for all"      +
                  " symmetric block ciphers. The cipher modes CFB (Cipher feedback), or OFB (Output "     +
                  "feedback) are valid for all block ciphers except AES. Other cipher modes like ECB "    +
                  "(Electronic Code Book), or CTS (Cipher Text Stealing) are only valid for RC2, 3DES, "  + 
                  "DES, MARS, AES, and RIJNDAEL with iv.{t:0,f:15}\n"                                     +
                  "\t-n  --padding\t {t:30,f:7}X923, ZEROS, ISO10126, or PKCS7 (by default). Modes: "     + 
                  "3FISH, AES, 3DES, DES, RC2, and RIJNDAEL. MARS only support PKCS7, and the others "    +
                  "block ciphers also support ISO7816D4 or TBC but no ZEROS padding mode. RSA and "       +
                  "ELGAMAL support PKCS1 (by default) and ISO9796D1 for RSA with Bouncy Castle."          + 
                  "{t:0,f:15}\n"                                                                          +
                  "\t-r  --random-gen      {t:30,f:7}Random password and salt generator. Modes: All "     +
                  "symmetric ciphers.{t:0,f:15}\n"                                                        +
                  "\t-l  --block-size      {t:30,f:7}The RIJNDAEL legal values: 128, 160, 192, 224, and " +
                  "256 (by default). The HC legal values: 128 (by default) or 256. For VMPC the value "   +
                  "must be between 8 and 6144 bits in increments of 8 bits (256 by default).{t:0,f:15}\n" +
                  "\t-z  --feedback-size   {t:30,f:7}For RIJNDAEL only. The feedback size determines the" +
                  " amount of data that is fed back to successive encryption or decryption operations. "  +
                  "The feedback size cannot be greater than the block size.{t:0,f:15}\n"                  +
                  "\t-y  --key-size\t{t:30,f:7}Key size in bits. Use the help combined with this "        +
                  "modifier to list or for more info.{t:0,f:15}\n"                                        +
                  "\t-g  --key-pair-gen    {t:30,f:7}Key pair generator. Modes: ECIES, DLIES, ELGAMAL, "  +
                  "NACCACHE, RSA, and PGP. The public and private key file names will be required."       +
                  "{t:0,f:15}\n"                                                                          +
                  "\t-b  --public-key      {t:30,f:7}Public key file name. Modes: ECIES, DLIES, RSA, PGP" +
                  ", NACCACHE, and ELGAMAL.{t:0,f:15}\n"                                                  +
                  "\t-v  --private-key     {t:30,f:7}Private key file name. Modes: ECIES, DLIES, RSA, "   +
                  "PGP, NACCACHE, and ELGAMAL.{t:0,f:15}\n"                                               +
                  "\t-9  --x509-file       {t:30,f:7}X509 certificate file name. Modes: RSA, PGP, and "   +
                  "all symmetric ciphers.{t:0,f:15}\n"                                                    +
                  "\t-0  --x509-store      {t:30,f:7}X509 common name or thumbprint in the certificate "  +
                  "store, Modes: RSA, PGP, and all symmetric ciphers.{t:0,f:15}\n"                        +
                  "\t-f  --format\t  {t:30,f:7}For Asymmetric keys. The available formats are: [XML] for" +
                  " intrinsic RSA mode; [B64] for RSA, ELGAMAL, NACCACHE, ECIES, and DLIES modes; "       +
                  "[ARMORED] for PGP mode.{t:0,f:15}\n"                                                   +
                  "\t-a  --oaep\t    {t:30,f:7}For ELGAMAL and RSA. Microsoft CryptoAPI only supports "   +
                  "OAEP since Windows XP for RSA.{t:0,f:15}\n"                                            +
                  "\t-q  --pgp-cipher      {t:30,f:7}Symmetric cipher for PGP encryption: AES128, AES192" +
                  " ,AES256 (by default), BLOWFISH, 2FISH, CAST5, DES, 3DES, IDEA, CAMELLIA128, "         + 
                  "CAMELLIA192, CAMELLIA256, and SAFER.{t:0,f:15}\n"                                      +
                  "\t-u  --crossbreeding   {t:30,f:7}For RSA, ELGAMAL, and PGP. It allows use either "    +
                  "keys from RSA to PGP and PGP to RSA or ELGAMAL to PGP and PGP to ELGAMAL.{t:0,f:15}\n" +
                  "\t-j  --tell-apart      {t:30,f:7}Sets customized password and salt for each file in " +
                  "batch process with symmetric ciphers.{t:0,f:15}\n"                                     +
                  "\t-o  --output\t  {t:30,f:7}Output file name or path.{t:0,f:15}\n"                     +
                  "\t-w  --overwrite       {t:30,f:7}Overwrites the existing output file(s) without "     +
                  "asking.{t:0,f:15}\n"                                                                   +
                  "\t-7  --io-options      {t:30,f:7}Input and output options. Use the help combined "    +
                  "with this modifier to list or for more info.{t:0,f:15}\n"                              +
                  "\t--export\t      {t:30,f:7}For RSA, PGP, and ELGAMAL. Exports certificates and keys." + 
                  " Use the help combined with this modifier to list or for more info.{t:0,f:15}\n"       +
                  "\t--encoding\t    {t:30,f:7}Character encoding for password, salt, key, and initial "  +
                  "vector with symmetric ciphers. The available encodings are: ASCII (by default), "      +
                  "UNICODE-LE, UNICODE-BE, UTF-7, UTF-8, and UTF-32.{t:0,f:15}\n"                         +
                  "\t--gost-box\t    {t:30,f:7}Specifies s-box for GOST mode. The available s-boxes are:" +
                  " DEFAULT, E-TEST, E-A, E-B, E-C, E-D, D-TEST, D-A, IV, or empty string for nothing at" +
                  " all.{t:0,f:15}\n"                                                                     +
                  "\t--without-iv-tweak    {t:30,f:7}Without tweak or initial vector if possible for "    +
                  "symmetric block ciphers. Uses Bouncy Castle.{t:0,f:15}\n"                              +
                  "\t--rsa-bouncy-castle   {t:30,f:7}Uses the Bouncy Castle for RSA, PGP, and all "       +
                  "symmetric ciphers with key exchange (Key pair generation, encription, and decryption)" +
                  ".{t:0,f:15}\n"                                                                         +
                  "\t--public-exponent     {t:30,f:7}Long prime number for RSA or PGP mode with RSA "     +
                  "algorithm and use of Bouncy Castle (65537 by default). Key pair generation only."      +
                  "{t:0,f:15}\n"                                                                          +
                  "\t--certainty\t   {t:30,f:7}Percentage of certainty when prime numbers are produced "  +
                  "with Bouncy Castle. For RSA, PGP, ELGAMAL, NACCACHE, ECDH, and DLIES modes. Key pair " +
                  "generation only.{t:0,f:15}\n"                                                          +
                  "\t--small-primes\t{t:30,f:7}Length of small primes for NACCACHE mode (30 by default)." +
                  "{t:0,f:15}\n"                                                                          +
                  "\t--signature\t   {t:30,f:7}Signature for encryption and decription. A file must be "  +
                  "specified and private key is required for RSA mode. You can specify Probabilistic "    +
                  "Signature Schema (PSS) or ISO9796D2 before the file (RSA mode only). Modes: RSA, "     + 
                  "NACCACHE, and ELGAMAL.{t:0,f:15}\n"                                                    +
                  "\t--pgp-id\t      {t:30,f:7}Identity for PGP key pair generation.{t:0,f:15}\n"         +
                  "\t--pgp-sha1\t    {t:30,f:7}Uses SHA1 with PGP for key pair generation.{t:0,f:15}\n"   +
                  "\t--pgp-algorithm       {t:30,f:7}Public and private keys algorithm for PGP mode. The" +
                  " available algorithms are: RSA (by default), ECDH, and ELGAMAL.{t:0,f:15}\n"           +
                  "\t--pgp-master\t  {t:30,f:7}Master key pair type for PGP. The available masters are: " +
                  "DSA (by default for ELGAMAL), ECDSA (by default for ECDH), and RSA.{t:0,f:15}\n"       +
                  "\t--pgp-signature       {t:30,f:7}Signature for PGP encryption and decription. The "   +
                  "key pair or certificates will be required.{t:0,f:15}\n"                                +
                  "\t--pgp-compress\t{t:30,f:7}Specifies a compression algorithm for encryption. The "    +
                  "available algorithms are: BZIP2, ZIP (by default), ZLIB, and NONE.{t:0,f:15}\n"        +
                  "\t--ies-cipher\t  {t:30,f:7}Symmetric cipher for ECIES and DLIES modes: AES (by "      +
                  "default), RIJNDAEL, SERPENT, TNEPRES, CAMELLIA, GOST, 2FISH, 3FISH, DES, 3DES, RC2, "  +
                  "RC5, RC6, SKIPJACK, BLOWFISH, CAST5, CAST6, TEA, XTEA, SEED, IDEA, NOEKEON, or empty " +
                  "string for nothing at all.{t:0,f:15}\n"                                                +
                  "\t--curve\t       {t:30,f:7}Specifies a curve name for ECIES mode and PGP with ECDSA " +
                  "master key or ECDH algorithm.{t:0,f:15}\n"                                             +
                  "\t--curve-store\t {t:30,f:7}Specifies a store of curves for ECIES mode and PGP with "  + 
                  "ECDSA master key or ECDH algorithm. The stores curve are: CUSTOM, TELETRUST, NIST, "   +
                  "ANSSI, X962, GOST, and SEC.{t:0,f:15}\n"                                               +
                  "\t--show-store-curves   {t:30,f:7}Shows the available curves in the specified store."  +
                  "{t:0,f:15}\n"                                                                          +
                  "\t--raise-pwd-exception {t:30,f:7}Raises exception for incorrect password or salt."    + 
                  "{t:0,f:15}\n"                                                                          +
                  "\t--inhibit-errors      {t:30,f:7}Continue even with errors if possible in batch "     +
                  "process.{t:0,f:15}\n"                                                                  +
                  "\t--inhibit-esc-chars   {t:30,f:7}Does not process hexadecimal byte notation by the "  +
                  "escape characters \\x or \\u for Unicode.{t:0,f:15}\n"                                 +
                  "\t--inhibit-delimiter   {t:30,f:7}Does not process semicolon as a path delimiter."     + 
                  "{t:0,f:15}\n"                                                                          +
                  "\t--input-notes\t {t:30,f:7}Show informative notes of input data.{t:0,f:15}\n"         +
                  "\t--examples\t    {t:30,f:7}Show command line examples for specified mode."            +
                  "{t:0,f:15}\n"                                                                          +
                  "\t--help\t\t{t:30,f:7}Show usage info. This modifier can be combined with others from" +
                  " behind or ahead for more info.{t:0,f:15}\n"
            );
        }
        
        //----------------------------------------------------------------------------------

        private static void ShowHelp (string cmd)
        {
            string s0 = "\n\t- ";
            string s1 = " (Blue Midnight Wish)";
            string s2 = " (Radio Gatun)";
            string s3 = " *";
            string s4 = "#";
            string s5 = "@";
            string s6 = "~";

            Program.ShowBanner();
            switch (cmd.ToLower())
            { 
                case MOD_SHORT_MODE:
                case MOD_LONG_MODE:
                    Messenger.Print
                    (
                          "\n Coders:\r\n"                                                      +
                          "\n\t- Bn (Base n, Where n must be a number from 2 to 64)\n\n"        +
                          "\r Symmetric Block Ciphers:\r\n"                                     +
                          "\n\t- RIJNDAEL"                                                      +
                          "\n\t- AES (Advanced Encryption Standard)"                            +
                          "\n\t- 3DES (Triple Data Encryption Standard)"                        +
                          "\n\t- DES (Data Encryption Standard)"                                +
                          "\n\t- RC2 (Rivest Cipher 2)"                                         +
                          "\n\t- RC5 (Rivest Cipher 5)"                                         +
                          "\n\t- RC6 (Rivest Cipher 6)"                                         +
                          "\n\t- MARS"                                                          +
                          "\n\t- SERPENT"                                                       +
                          "\n\t- TNEPRES"                                                       + 
                          "\n\t- 2FISH (Twofish)"                                               +
                          "\n\t- 3FISH (Threefish)"                                             +
                          "\n\t- BLOWFISH"                                                      +
                          "\n\t- CAST5"                                                         +
                          "\n\t- CAST6"                                                         +
                          "\n\t- IDEA (International Data Encryption Algorithm)"                +
                          "\n\t- GOST (The Government Standard of the USSR 28147)"              +
                          "\n\t- NOEKEON"                                                       +
                          "\n\t- SEED"                                                          +
                          "\n\t- TEA"                                                           +
                          "\n\t- XTEA"                                                          +
                          "\n\t- SKIPJACK\n\n"                                                  +
                          "\r Symmetric Stream Ciphers:\r\n"                                    +
                          "\n\t- RC4 (Rivest Cipher 4)"                                         +
                          "\n\t- ISAAC"                                                         +
                          "\n\t- SALSA20"                                                       +
                          "\n\t- XSALSA20"                                                      +
                          "\n\t- CHACHA"                                                        +
                          "\n\t- VMPC (Variably Modified Permutation Composition)"              +
                          "\n\t- HC (Hongjun Cipher)\n\n"                                       +
                          "\r Asymmetric Ciphers:\r\n"                                          +
                          "\n\t- RSA (Rivest, Shamir and Adleman)"                              +
                          "\n\t- PGP (Pretty Good Privacy, Open, RFC 4880)"                     +
                          "\n\t- ELGAMAL"                                                       +
                          "\n\t- NACCACHE\n\n"                                                  +
                          "\r Hybrids:\r\n"                                                     +
                          "\n\t- ECIES (Elliptic Curve Integrated Encryption Scheme)"           +
                          "\n\t- DLIES (Discrete Logarithm Integrated Encryption Scheme)\n\n"   +
                          "\r Others:\r\n"                                                      +
                          "\n\t- DIGEST (Digest file mode)"                                     +
                          "\n\t- CHECKSUM (Checksum file mode)\n"
                        , new ConsoleColor[]
                          {
                                ConsoleColor.Yellow
                              , ConsoleColor.Gray
                              
                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray
                          }
                   );
                   break;

                case MOD_SHORT_HASH:
                case MOD_LONG_HASH:
                    Messenger.Print
                    (
                          "\n SHA-3 (Candidates):\r\n"                                      +     
                          s0 + HASH_BLAKE224                                                +
                          s0 + HASH_BLAKE256                                                +
                          s0 + HASH_BLAKE384                                                +
                          s0 + HASH_BLAKE512                                                +
                          s0 + HASH_BMW224                                                  + s1 +
                          s0 + HASH_BMW256                                                  + s1 +
                          s0 + HASH_BMW384                                                  + s1 +
                          s0 + HASH_BMW512                                                  + s1 +
                          s0 + HASH_CUBE224                                                 +
                          s0 + HASH_CUBE256                                                 +
                          s0 + HASH_CUBE384                                                 +
                          s0 + HASH_CUBE512                                                 +
                          s0 + HASH_ECHO224                                                 +
                          s0 + HASH_ECHO256                                                 +
                          s0 + HASH_ECHO384                                                 +
                          s0 + HASH_ECHO512                                                 +
                          s0 + HASH_FUGUE224                                                +
                          s0 + HASH_FUGUE256                                                +
                          s0 + HASH_FUGUE384                                                +
                          s0 + HASH_FUGUE512                                                +
                          s0 + HASH_GROESTL224                                              +
                          s0 + HASH_GROESTL256                                              +
                          s0 + HASH_GROESTL384                                              +
                          s0 + HASH_GROESTL512                                              +
                          s0 + HASH_HAMSI224                                                +
                          s0 + HASH_HAMSI256                                                +
                          s0 + HASH_HAMSI384                                                +
                          s0 + HASH_HAMSI512                                                +
                          s0 + HASH_JH224                                                   +
                          s0 + HASH_JH256                                                   +
                          s0 + HASH_JH384                                                   +
                          s0 + HASH_JH512                                                   +
                          s0 + HASH_KECCAK224                                               + s3 +
                          s0 + HASH_KECCAK256                                               + s3 +
                          s0 + HASH_KECCAK384                                               + s3 +
                          s0 + HASH_KECCAK512                                               + s3 +
                          s0 + HASH_LUFFA224                                                +
                          s0 + HASH_LUFFA256                                                +
                          s0 + HASH_LUFFA384                                                +
                          s0 + HASH_LUFFA512                                                +
                          s0 + HASH_SHABAL224                                               +
                          s0 + HASH_SHABAL256                                               +
                          s0 + HASH_SHABAL384                                               +
                          s0 + HASH_SHABAL512                                               +
                          s0 + HASH_SHAVITE_224                                             +
                          s0 + HASH_SHAVITE_256                                             +
                          s0 + HASH_SHAVITE_384                                             +
                          s0 + HASH_SHAVITE_512                                             +
                          s0 + HASH_SIMD224                                                 +
                          s0 + HASH_SIMD256                                                 +
                          s0 + HASH_SIMD384                                                 +
                          s0 + HASH_SIMD512                                                 +
                          s0 + HASH_SKEIN224                                                +
                          s0 + HASH_SKEIN256                                                + s3 +
                          s0 + HASH_SKEIN384                                                +
                          s0 + HASH_SKEIN512                                                + s3 +
                          "\n\n \rSHA-2:\r\n"                                               +
                          s0 + HASH_SHA224                                                  + s3 + s4 + s5 + s6                   +
                          s0 + HASH_SHA256                                                  + s3 + s4 + s5 + s6                   +
                          s0 + HASH_SHA384                                                  + s3 + s4 + s5 + s6                   +
                          s0 + HASH_SHA512                                                  + s3 + s4 + s5 + s6 + " (By default)" +
                          "\n\n \rSHA (Old):\r\n"                                           +
                          s0 + HASH_SHA1                                                    + s3 + s4 + s5 + s6 +
                          s0 + HASH_SHA0                                                    +
                          "\n\n \rMD (Message Digest):\r\n"                                 +
                          s0 + HASH_MD2                                                     + s3 + s4 + s5 +
                          s0 + HASH_MD4                                                     + s3 + s5      +
                          s0 + HASH_MD5                                                     + s3 + s4 + s5 + s6 + 
                          "\n\n \rRace Integrity Primitives Evaluation Message Digest:\r\n" +
                          s0 + HASH_RIPEMD                                                  +
                          s0 + HASH_RIPEMD128                                               + s3 + s5      +
                          s0 + HASH_RIPEMD160                                               + s3 + s4 + s5 +
                          s0 + HASH_RIPEMD256                                               + s3 + s5      +
                          s0 + HASH_RIPEMD320                                               + s3 +
                          "\n\n \rOthers (32-bits):\r\n"                                    +
                          s0 + HASH_AP                                                      +
                          s0 + HASH_BERNSTEIN                                               +
                          s0 + HASH_BERNSTEIN1                                              +
                          s0 + HASH_BKDR                                                    +
                          s0 + HASH_DEK                                                     +
                          s0 + HASH_DJB                                                     +
                          s0 + HASH_DOTNET                                                  +
                          s0 + HASH_ELF                                                     +
                          s0 + HASH_FNV                                                     +
                          s0 + HASH_FNV1A                                                   +
                          s0 + HASH_JENKINS3                                                +
                          s0 + HASH_JS                                                      +
                          s0 + HASH_MURMUR2                                                 +
                          s0 + HASH_MURMUR3                                                 +
                          s0 + HASH_ONEATTIME                                               +
                          s0 + HASH_PJW                                                     +
                          s0 + HASH_ROTATING                                                +
                          s0 + HASH_RS                                                      +
                          s0 + HASH_SDBM                                                    +
                          s0 + HASH_SHIFTANDXOR                                             + " (Shift And Xor)" +
                          s0 + HASH_SUPERFAST                                               +
                          "\n\n \rOthers (64-bits):\r\n"                                    +
                          s0 + HASH_FNV64                                                   +
                          s0 + HASH_FNV1A64                                                 +
                          s0 + HASH_MURMUR2_64                                              +
                          s0 + HASH_SIPHASH                                                 +
                          "\n\n \rOthers (128-bits):\r\n"                                   +
                          s0 + HASH_MURMUR3_128                                             +
                          "\n\n \rOthers:\r\n"                                              +
                          s0 + GOST                                                         +
                          s0 + HASH_GRINDAHL256                                             +
                          s0 + HASH_GRINDAHL512                                             +
                          s0 + HASH_HAS160                                                  +
                          s0 + HASH_HAVAL3_128                                              +
                          s0 + HASH_HAVAL3_160                                              +
                          s0 + HASH_HAVAL3_192                                              +
                          s0 + HASH_HAVAL3_224                                              +
                          s0 + HASH_HAVAL3_256                                              +
                          s0 + HASH_HAVAL4_128                                              +
                          s0 + HASH_HAVAL4_160                                              +
                          s0 + HASH_HAVAL4_192                                              +
                          s0 + HASH_HAVAL4_224                                              +
                          s0 + HASH_HAVAL4_256                                              +
                          s0 + HASH_HAVAL5_128                                              +
                          s0 + HASH_HAVAL5_160                                              +
                          s0 + HASH_HAVAL5_192                                              +
                          s0 + HASH_HAVAL5_224                                              +
                          s0 + HASH_HAVAL5_256                                              +
                          s0 + HASH_PANAMA                                                  +
                          s0 + HASH_RG32                                                    + s2 +
                          s0 + HASH_RG64                                                    + s2 +
                          s0 + HASH_SNEFRU4_128                                             +
                          s0 + HASH_SNEFRU4_256                                             +
                          s0 + HASH_SNEFRU8_128                                             +
                          s0 + HASH_SNEFRU8_256                                             +
                          s0 + HASH_TIGER2                                                  +
                          s0 + HASH_TIGER3_192                                              + 
                          s0 + HASH_TIGER4_192                                              +
                          s0 + HASH_WHIRLPOOL                                               + s3 +
                          "\n\n \rChecksum:\r\n"                                            +
                          s0 + HASH_ADLER32                                                 +
                          s0 + HASH_CRC32_IEEE                                              +
                          s0 + HASH_CRC32_CASTAGNOLI                                        +
                          s0 + HASH_CRC32_KOOPMAN                                           +
                          s0 + HASH_CRC32_Q                                                 +
                          s0 + HASH_CRC64_ISO                                               +
                          s0 + HASH_CRC64_ECMA                                              +
                          "\n\n * DLIES and ECIES modes."                                   +
                          "\n # Signature for PGP mode."                                    +
                          "\n @ Signature for RSA, ELGAMAL, and NACCACHE modes."            +
                          "\n ~ OAEP with Bouncy Castle.\n"
                        , new ConsoleColor[]
                          {
                                ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray

                              , ConsoleColor.Yellow
                              , ConsoleColor.Gray
                          }
                   );
                   break;

                case MOD_SHORT_KEY_SIZE:
                case MOD_LONG_KEY_SIZE:
                   Messenger.Print
                  (
                          "\n {f:14}>{t:3,f:7} RC2, RC5, CAST5, and SKIPJACK supports key sizes from 40 to 128 "  +
                          "bits in increments of 8 bits (128 by default).{t:0,f:14}\n"                            +
                          " >{t:3,f:7} RC6 supports key sizes from 40 to 256 bits in increments of 8 bits "       +
                          "(256 by default).{t:0,f:14}\n"                                                         +
                          " >{t:3,f:7} RC4 supports key sizes from 40 to 2048 bits in increments of 8 bits "      +
                          "(256 by default).{t:0,f:14}\n"                                                         +
                          " >{t:3,f:7} MARS supports key sizes from 128 to 448 bits in increments of 8 bits"      +
                          " (256 by default).{t:0,f:14}\n"                                                        +
                          " >{t:3,f:7} BLOWFISH supports key sizes from 40 to 448 bits in increments of 8 "       +
                          "bits (256 by default).{t:0,f:14}\n"                                                    +
                          " >{t:3,f:7} 3FISH supports key sizes of 256, 512, and 1024 bits (256 by default)"      +
                          ".{t:0,f:14}\n"                                                                         +
                          " >{t:3,f:7} CAMELLIA, CAST6, 3DES, AES, 2FISH, SERPENT, TNEPRES, and RIJNDAEL "        +
                          "supports keys of 128, or 192 (by default for 3DES), and 256 bits (by default for "     +
                          "CAST6, AES, 2FISH, SERPENT, TNEPRES, CAMELLIA, and RIJNDAEL).{t:0,f:14}\n"             +
                          " >{t:3,f:7} SALSA20, CHAHA, and HC supports key sizes of 128 or 256 bits (by "         +
                          "default).{t:0,f:14}\n"                                                                 +
                          " >{t:3,f:7} VMPC supports key sizes from 40 to 6144 bits in increments of 8 bits"      +
                          " (256 by default).{t:0,f:14}\n"                                                        +
                          " >{t:3,f:7} ISAAC supports key sizes from 32 to 8192 bits in increments of 16 "        +
                          "bits (256 by default).{t:0,f:14}\n"                                                    +
                          " >{t:3,f:7} NACCACHE and ELGAMAL can be any key size since 256 bits in increments"     +
                          " of 8 bits (768 by default). However, a considerably large key can greatly  increase " +
                          "processing time.{t:0,f:14}\n"                                                          +
                          " >{t:3,f:7} RSA and PGP with RSA algorithm supports key sizes from 384 to 16384 "      +
                          "bits in increments of 8 bits if you have Mono or Microsoft Enhanced Cryptographic"     +
                          " Provider installed. It supports key sizes from 384 to 512 bits in increments of 8 "   +
                          "bits if you have the Microsoft Base Cryptographic Provider installed. 1024 is the "    +
                          "default value for RSA and PGP mode with Mono or Microsoft Enhanced Cryptographic "     +
                          "Provider, and 512 with Microsoft Base Cryptographic Provider.{t:0,f:14}\n"             +
                          " >{t:3,f:7} ECDH supports key sizes of 192, 224, 239, 256, 384, and 521.{t:0,f:14}\n"
                   );
                   break;

                case MOD_LONG_EXPORT:
                    Messenger.Print
                   (
                       "\n{f:14} Certificate to RSA Keys:\n\n"                                         +
                       "\t{t:15,f:7}crypto -m rsa -9 file.cer --export -b pubic.key{t:0}\n"            +
                       "\t{t:15}crypto -m rsa -9 file.pfx --export -b pubic.key -v private.key{t:0}\n" +
                       "\t{t:15}crypto -m rsa -9 file.pfx -p \"my password\" --export -b pubic.key "   +
                       "-v private.key{t:0}\n"                                                         +
                       "\n{f:14} RSA to PGP Keys:\n\n"                                                 +
                       "\t{t:15,f:7}crypto -m rsa -b rsa-public.key --export -b pgp-pubic.key{t:0}\n"  +
                       "\t{t:15}crypto -m rsa -v rsa-private.key --export -b pgp-pubic.key "           +
                       "-v pgp-private.key --pgp-sha1{t:0}\n"                                          +
                       "\t{t:15}crypto -m rsa -v rsa-private.key --export -b pgp-pubic.key "           +
                       "-v pgp-private.key -p \"my private key password\" --pgp-sha1{t:0}\n"           +
                       "\n{f:14} Certificate to PGP Keys:\n\n"                                         +
                       "\t{t:15,f:7}crypto -m pgp -9 file.cer --export -b pubic.key{t:0}\n"            +
                       "\t{t:15}crypto -m pgp -9 file.pfx --export -b pubic.key -v private.key{t:0}\n" +
                       "\t{t:15}crypto -m pgp -9 file.pfx -p \"my certificate password\" --export "    +
                       "-b pubic.key -v private.key -p \"my private key password\" --pgp-sha1{t:0}\n"  +
                       "\n{f:14} PGP to RSA Keys:\n\n"                                                 +
                       "\t{t:15,f:7}crypto -m pgp -b pgp-public.key --export -b rsa-pubic.key\n{t:0}"  +
                       "\t{t:15}crypto -m pgp -v pgp-private.key --export -b rsa-pubic.key "           +
                       "-v rsa-private.key{t:0}\n"                                                     +
                       "\t{t:15}crypto -m pgp -v pgp-private.key -p \"my password\" --export "         +
                       "-b rsa-pubic.key -v rsa-private.key{t:0}\n"                                    +
                       "\n{f:14} PGP to ECDH Keys:\n\n"                                                +
                       "\t{t:15,f:7}crypto -m pgp --pgp-algorithm ecdh -b pgp-public.key "             +
                       "-v pgp-private.key --export -b ecdh-pubic.key -v ecdh-private.key{t:0}\n"      +
                       "\n{f:14} ECDH to PGP Keys:\n\n"                                                +
                       "\t{t:15,f:7}crypto -m ecdh -b ecdh-public.key -v ecdh-private.key --export "   +
                       "-b pgp-public.key -v pgp-private.key{t:0}\n"                                   +
                       "\n{f:14} PGP to ELGAMAL Keys:\n\n"                                             +
                       "\t{t:15,f:7}crypto -m pgp --pgp-algorithm elgamal -b pgp-public.key "          +
                       "-v pgp-private.key -p \"my password\" --export -b elgamal-pubic.key -v "       +
                       "elgamal-private.key{t:0}\n"                                                    +
                       "\n{f:14} ELGAMAL to PGP Keys:\n\n"                                             +
                       "\t{t:15,f:7}crypto -m elgamal -b elgamal-public.key -v elgamal-private.key "   +
                       "--export -b pgp-public.key -v pgp-private.key -p \"my password\" "             +
                       "--pgp-sha1{t:0}\n"
                   );
                   break;

                case MOD_SHORT_IO_OPTIONS:
                case MOD_LONG_IO_OPTIONS:
                   Messenger.Print
                   (
                       "\n Input output options separated by commas:\n\r"          +
                       "\n\t- BASIC (by default): Basic wildcards patterns."       +
                       "\n\t- GLOB: Globbing patterns."                            +
                       "\n\t- EXTGLOB: Extended globbing patterns."                +
                       "\n\t- REGEX: Regular expressions patterns."                +
                       "\n\t- UNIGNORE-CASE: Case sensitive."                      +
                       "\n\t- RECURSIVELY: Search for patterns recursively."       +
                       "\n\t- REVERSE: Search for patterns inversely.\n"           +
                       "\n\r Character escape (for glob, extglob, and regex):\n\r" +
                       "\n\t- Windows: /"                                          +
                       "\n\t- Others:  \\\n"                                       +
                       "\n\r Examples:\n\r"                                        +
                       "\n\tcrypto -m aes -e \"/my path/my file?.*\""              +
                       "\n\tcrypto -m aes -7 extglob,unignore-case -e \\"          +
                       "\n\t        \"/my path/+([my[:space:]])file[0-9].*\"\n"
                       , new ConsoleColor[]
                         {
                              ConsoleColor.Yellow
                            , ConsoleColor.Gray

                            , ConsoleColor.Yellow
                            , ConsoleColor.Gray

                            , ConsoleColor.Yellow
                            , ConsoleColor.Gray
                         }
                   );
                   break;

                default:
                   throw new Exception("Unsupported modifier with combined help!");
            }

            Environment.Exit(0);
        }

        //----------------------------------------------------------------------------------

        private static void ShowExamples (string mode)
        {
            Program.ShowBanner();

            byte   b, n = 128;
            string r1 = "#1";
            string r2 = "#2";
            string s1 = "\n\n [f:6]<{0}>\n"                                            +
                        "\n [f:14]Encode:[f:7]\n\n"                                    +
                        "\tcrypto [t:15]-o file.{1} -m {1} -e file.txt[t:0]\n"         +
                        "\tcrypto [t:15]-o file.{1} -m {1} -6 {2} -e file.txt[t:0]\n"  + 
                        r1                                                             +
                        "\tcrypto [t:15]-o file.{1} -m {1} -1 {3} -e file.txt[t:0]\n"  +
                        "\n [f:14]Decode:[f:7]\n\n"                                    +
                        "\tcrypto [t:15]-o file.txt -m {1} -d file.{1}[t:0]\n" + r2    +
                        "\tcrypto [t:15]-o file.txt -m {1} -1 {3} -d file.{1}[t:0]\n";

            string s2 = "\n\n [f:6]<{0}>\n"                                                                       +
                        "\n [f:14]Encryption:[f:7]\n\n"                                                           +
                        "\tcrypto [t:15]-o file.{1} -m {2} -e file.bin[t:0]\n"                                    +
                        "\tcrypto [t:15]-o file.{1} -m {2} -p \"my password\" -s \"my salt8\" -e file.bin[t:0]\n" +
                        "\tcrypto [t:15]-o file.{1} -m {2} -p file:\"my password file.txt\" -e file.bin[t:0]\n"   +
                        "\tcrypto [t:15]-o file.{1} -m {2} -s \"\" -h sha1 -e file.bin[t:0]\n"                    +
                        "\tcrypto [t:15]-o file.{1} -m {2} -b rsa-public.key -e file.bin[t:0]\n"                  +
                        "\tcrypto [t:15]-o file.{1} -m {2} -b elgamal-public.key -e file.bin[t:0]\n"              +
                        "\tcrypto [t:15]-o file.{1} -m {2} -b naccache-public.key -e file.bin[t:0]\n"             +
                        "\tcrypto [t:15]-o file.{1} -m {2} -b ecdh-public.key -v ecdh-private.key "               +
                        "-e file.bin[t:0]\n"                                                                      +
                        "\tcrypto [t:15]-o file.{1} -m {2} -9 public.cer -e file.bin[t:0]\n"                      +
                        "\tcrypto [t:15]-o file.{1} -m {2} -9 public.pem -e file.bin[t:0]\n"                      +
                        "\tcrypto [t:15]-o file.{1} -m {2} -y 128 -k 1234567890123456 "                           +
                        "-i 6543210987654321 -e file.bin[t:0]\n"                                                  +
                        "\n [f:14]Decryption:[f:7]\n\n"                                                           +
                        "\tcrypto [t:15]-o file.bin -m {2} -d file.{1}[t:0]\n"                                    +
                        "\tcrypto [t:15]-o file.bin -m {2} -p \"my password\" -s \"my salt8\" -d file.{1}[t:0]\n" +
                        "\tcrypto [t:15]-o file.bin -m {2} -p file:\"my password file.txt\" -d file.{1}[t:0]\n"   +
                        "\tcrypto [t:15]-o file.bin -m {2} -s \"\" -h sha1 -d file.{1}[t:0]\n"                    +
                        "\tcrypto [t:15]-o file.bin -m {2} -v rsa-private.key -d file.{1}[t:0]\n"                 +
                        "\tcrypto [t:15]-o file.bin -m {2} -v elgamal-private.key -d file.{1}[t:0]\n"             +
                        "\tcrypto [t:15]-o file.bin -m {2} -v naccache-private.key -d file.{1}[t:0]\n"            +
                        "\tcrypto [t:15]-o file.bin -m {2} -b ecdh-public.key -v ecdh-private.key "               +
                        "-d file.{1}[t:0]\n"                                                                      +
                        "\tcrypto [t:15]-o file.bin -m {2} -v private.pfx -d file.{1}[t:0]\n"                     +
                        "\tcrypto [t:15]-o file.bin -m {2} -v private.pem -d file.{1}[t:0]\n"                     +
                        "\tcrypto [t:15]-o file.bin -m {2} -y 128 -k 1234567890123456 "                           +
                        "-i 6543210987654321 -d file.{1}[t:0]\n";

            string s3 = "-y 128 ";
            string s4 = "\n\n [f:6]<{0}>\n"                                                            +
                        "\n [f:14]Encryption:[f:7]\n\n"                                                +
                        "\tcrypto [t:15]-o file.{1} -m {2} -e file.bin[t:0]\n"                         +
                        "\tcrypto [t:15]-o file.{1} -m {2} {3}-k 1234567890123456 -e file.bin[t:0]\n"  +
                        "\tcrypto [t:15]-o file.{1} -m {2} -s \"\" -h sha1 -e file.bin[t:0]\n"         +
                        "\tcrypto [t:15]-o file.{1} -m {2} -b rsa-public.key -e file.bin[t:0]\n"       +
                        "\tcrypto [t:15]-o file.{1} -m {2} -b elgamal-public.key -e file.bin[t:0]\n"   +
                        "\tcrypto [t:15]-o file.{1} -m {2} -b naccache-public.key -e file.bin[t:0]\n"  +
                        "\tcrypto [t:15]-o file.{1} -m {2} -b ecdh-public.key -v ecdh-private.key "    +
                        "-e file.bin[t:0]\n"                                                           +
                        "\tcrypto [t:15]-o file.{1} -m {2} -9 public.cer -e file.bin[t:0]\n"           +
                        "\tcrypto [t:15]-o file.{1} -m {2} -9 public.pem -e file.bin[t:0]\n"           +
                        "\tcrypto [t:15]-o file.{1} -m {2} -p \"my password\" -s \"my salt8\" "        +
                        "-e file.bin[t:0]\n"                                                           +
                        "\tcrypto [t:15]-o file.{1} -m {2} -p file:\"my password file.txt\" "          +
                        "-e file.bin[t:0]\n"                                                           +
                        "\n [f:14]Decryption:[f:7]\n\n"                                                +
                        "\tcrypto [t:15]-o file.bin -m {2} -d file.{1}[t:0]\n"                         +
                        "\tcrypto [t:15]-o file.bin -m {2} {3}-k 1234567890123456 -d file.{1}[t:0]\n"  +
                        "\tcrypto [t:15]-o file.bin -m {2} -s \"\" -h sha1 -d file.{1}[t:0]\n"         +
                        "\tcrypto [t:15]-o file.bin -m {2} -v rsa-private.key -d file.{1}[t:0]\n"      +
                        "\tcrypto [t:15]-o file.bin -m {2} -v elgamal-private.key -d file.{1}[t:0]\n"  +
                        "\tcrypto [t:15]-o file.bin -m {2} -v naccache-private.key -d file.{1}[t:0]\n" +
                        "\tcrypto [t:15]-o file.bin -m {2} -b ecdh-public.key -v ecdh-private.key "    +
                        "-d file.{1}[t:0]\n"                                                           +
                        "\tcrypto [t:15]-o file.bin -m {2} -9 private.pfx -d file.{1}[t:0]\n"          +
                        "\tcrypto [t:15]-o file.bin -m {2} -9 private.pem -d file.{1}[t:0]\n"          +
                        "\tcrypto [t:15]-o file.bin -m {2} -p \"my password\" -s \"my salt8\" "        +
                        "-d file.{1}[t:0]\n"                                                           +
                        "\tcrypto [t:15]-o file.bin -m {2} -p file:\"my password file.txt\" "          +
                        "-d file.{1}[t:0]\n";

            switch (mode = mode.ToUpper())
            {
                case B7:
                case B8:
                case B9:
                case B10:
                case B11:
                case B12:
                case B13:
                case B14:
                case B15:
                    n = 126;
                    goto case B64;

                case B2:
                case B3:
                case B4:
                case B5:
                case B6:
                case B16:
                case B17:
                case B18:
                case B19:
                case B20:
                case B21:
                case B22:
                case B23:
                case B24:
                case B25:
                case B26:
                case B27:
                case B28:
                case B29:
                case B30:
                case B31:
                case B32:
                case B33:
                case B34:
                case B35:
                case B36:
                case B37:
                case B38:
                case B39:
                case B40:
                case B41:
                case B42:
                case B43:
                case B44:
                case B45:
                case B46:
                case B47:
                case B48:
                case B49:
                case B50:
                case B51:
                case B52:
                case B53:
                case B54:
                case B55:
                case B56:
                case B57:
                case B58:
                case B59:
                case B60:
                case B61:
                case B62:
                case B63:
                case B64:
                    s2 = CODE.Substring(0, b = byte.Parse(mode.Substring(1)));

                    if (b == 32 || b == 64)
                    {
                        s1 = s1.Replace(r1, "\tcrypto [t:15]-o file.{1} -m {1} -8 -e file.txt[t:0]\n");
                        s1 = s1.Replace(r2, "\tcrypto [t:15]-o file.txt -m {1} -8 -d file.{1}[t:0]\n");
                    }

                    else
                    {
                        s1 = s1.Replace(r1, string.Empty);
                        s1 = s1.Replace(r2, string.Empty);
                    }

                    Messenger.Print(string.Format(s1, "BASE-" + b, mode.ToLower(), n, s2));
                    break;

                case DIGEST:
                    Messenger.Print
                    (
                          "\n\n {f:6}<DIGEST>{f:7}\n\n"                                 +
                          "\tcrypto {t:15}-m digest file.bin{t:0}\n"                    +
                          "\tcrypto {t:15}-m digest -h sha256 file.bin{t:0}\n"          +
                          "\tcrypto {t:15}-o file.txt -m digest -h md5 file.bin{t:0}\n"
                    );
                    break;

                case CHECKSUM:
                    Messenger.Print
                    (
                          "\n\n {f:6}<CHECKSUM>{f:7}\n\n"                                        +
                          "\tcrypto {t:15}-m checksum -h adler32 file.bin{t:0}\n"                +
                          "\tcrypto {t:15}-o file.txt -m checksum -h crc32-ieee file.bin{t:0}\n"
                    );
                    break;

                case AES:
                    Messenger.Print
                    (
                          string.Format
                          (
                                 s2
                               , AES
                               , AES.ToLower()
                               , AES.ToLower()
                          )
                    );
                    break;

                case RIJNDAEL:
                    Messenger.Print
                    (
                          "\n {f:6}<RIJNDAEL>\n"                                                              +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                     +
                          "\tcrypto {t:15}-o file.rij -m rijndael -e file.bin{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.rij -m rijndael -s \"\" -h sha1 -e file.bin{t:0}\n"         +
                          "\tcrypto {t:15}-o file.rij -m rijndael -b rsa-public.key -e file.bin{t:0}\n"       + 
                          "\tcrypto {t:15}-o file.rij -m rijndael -b elgamal-public.key -e file.bin{t:0}\n"   +
                          "\tcrypto {t:15}-o file.rij -m rijndael -b naccache-public.key -e file.bin{t:0}\n"  +
                          "\tcrypto {t:15}-o file.rij -m rijndael -b ecdh-public.key -v ecdh-private.key "    +
                          "-e file.bin{t:0}\n"                                                                +
                          "\tcrypto {t:15}-o file.rij -m rijndael -9 public.cer -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file.rij -m rijndael -9 public.pem -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file.rij -m rijndael -y 128 -l 128 -k 1234567890123456 "         +
                          "-i 6543210987654321 -e file.bin{t:0}\n"                                            +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                     +
                          "\tcrypto {t:15}-o file.bin -m rijndael -d file.rij{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.bin -m rijndael -s \"\" -h sha1 -d file.rij{t:0}\n"         +
                          "\tcrypto {t:15}-o file.bin -m rijndael -v rsa-private.key -d file.rij{t:0}\n"      +
                          "\tcrypto {t:15}-o file.bin -m rijndael -v elgamal-private.key -d file.rij{t:0}\n"  +
                          "\tcrypto {t:15}-o file.bin -m rijndael -v naccache-private.key -d file.rij{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m rijndael -b ecdh-public.key -v ecdh-private.key "    +
                          "-d file.rij{t:0}\n"                                                                +
                          "\tcrypto {t:15}-o file.bin -m rijndael -9 private.cer -d file.rij{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m rijndael -9 private.pem -d file.rij{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m rijndael -y 128 -l 128 -k 1234567890123456 "         +
                          "-i 6543210987654321 -d file.rij{t:0}\n"
                    );
                    break;

                case TDES:
                    Messenger.Print
                    (
                          string.Format
                          (
                                  s2
                                , "TRIPLE-DES"
                                , TDES.ToLower()
                                , TDES.ToLower()
                          )
                    );
                    break;

                case DES:
                    Messenger.Print
                    (
                          "\n\n {f:6}<DES>\n"                                                            +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                +
                          "\tcrypto {t:15}-o file.des -m des -e file.bin{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.des -m des -p \"my password\" -s \"my salt8\" "        +
                          "-e file.bin{t:0}\n"                                                           +
                          "\tcrypto {t:15}-o file.des -m des -p file:\"my password file.txt\" "          +
                          "-e file.bin{t:0}\n"                                                           +
                          "\tcrypto {t:15}-o file.des -m des -s \"\" -h sha1 -e file.bin{t:0}\n"         +
                          "\tcrypto {t:15}-o file.des -m des -b rsa-public.key -e file.bin{t:0}\n"       +
                          "\tcrypto {t:15}-o file.des -m des -b elgamal-public.key -e file.bin{t:0}\n"   +
                          "\tcrypto {t:15}-o file.des -m des -b naccache-public.key -e file.bin{t:0}\n"  +
                          "\tcrypto {t:15}-o file.des -m des -b ecdh-public.key -v ecdh-private.key "    +
                          "-e file.bin{t:0}\n"                                                           +
                          "\tcrypto {t:15}-o file.des -m des -9 public.cer -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file.des -m des -9 public.pem -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file.des -m des -k 12345678 -i 87654321 -e file.bin{t:0}\n" +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                +
                          "\tcrypto {t:15}-o file.bin -m des -d file.des{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.bin -m des -p \"my password\" -s \"my salt8\" "        +
                          "-d file.des{t:0}\n"                                                           +
                          "\tcrypto {t:15}-o file.bin -m des -p file:\"my password file.txt\" "          +
                          "-d file.des{t:0}\n"                                                           +
                          "\tcrypto {t:15}-o file.bin -m des -s \"\" -h sha1 -d file.des{t:0}\n"         +
                          "\tcrypto {t:15}-o file.bin -m des -v rsa-private.key -d file.des{t:0}\n"      +
                          "\tcrypto {t:15}-o file.bin -m des -v elgamal-private.key -d file.des{t:0}\n"  +
                          "\tcrypto {t:15}-o file.bin -m des -v naccache-private.key -d file.des{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m des -b ecdh-public.key -v ecdh-private.key "    +
                          "-d file.des{t:0}\n"                                                           +
                          "\tcrypto {t:15}-o file.bin -m des -9 private.pfx -d file.des{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m des -9 private.pem -d file.des{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m des -k 12345678 -i 87654321 "                   +
                          "-d file.des{t:0}\n"
                    );
                    break;

                case MARS:
                    Messenger.Print
                    (
                          string.Format
                          (
                                  s2
                                , MARS
                                , MARS.Substring(0, 3).ToLower(), MARS.ToLower()
                          )
                    );
                    break;

                case SALSA20:
                case CHACHA:
                    mode = mode.ToLower();
                    r1   = mode.Substring(0, 3);
                    
                    Messenger.Print
                    (
                          "\n\n {f:6}<" + mode.ToUpper() + ">\n"                                                         +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                                +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -e file.bin{t:0}\n"                         +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -s \"\" -h sha1 -e file.bin{t:0}\n"         +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -b rsa-public.key -e file.bin{t:0}\n"       +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -b elgamal-public.key -e file.bin{t:0}\n"   +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -b naccache-public.key -e file.bin{t:0}\n"  +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -b ecdh-public.key -v ecdh-private.key"     +
                          " -e file.bin{t:0}\n"                                                                          +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -9 public.cer -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -9 public.pem -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file." + r1 + " -m " + mode + " -y 128 -k 1234567890123456"                 +
                          " -i 87654321 -e file.bin{t:0}\n"                                                              +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                                +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -d file." + r1 + "{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -s \"\" -h sha1 -d file." + r1 + "{t:0}\n"         +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -v rsa-private.key -d file." + r1 + "{t:0}\n"      +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -v elgamal-private.key -d file." + r1 + "{t:0}\n"  +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -v naccache-private.key -d file." + r1 + "{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -b ecdh-public.key -v ecdh-private.key"            +
                          " -d file." + r1 + "{t:0}\n"                                                                   +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -9 private.pfx -d file." + r1 + "{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -9 private.pem -d file." + r1 + "{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m " + mode + " -y 128 -k 1234567890123456"                        +
                          " -i 87654321 -d file." + r1 + "{t:0}\n"
                    );
                    break;

                case XSALSA20:
                    Messenger.Print
                    (
                          "\n\n {f:6}<XSALSA20>\n"                                                            +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                     +
                          "\tcrypto {t:15}-o file.x20 -m xsalsa20 -e file.bin{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.x20 -m xsalsa20 -s \"\" -h sha1 -e file.bin{t:0}\n"         +
                          "\tcrypto {t:15}-o file.x20 -m xsalsa20 -b rsa-public.key -e file.bin{t:0}\n"       +
                          "\tcrypto {t:15}-o file.x20 -m xsalsa20 -b elgamal-public.key -e file.bin{t:0}\n"   +
                          "\tcrypto {t:15}-o file.x20 -m xsalsa20 -b naccache-public.key -e file.bin{t:0}\n"  +
                          "\tcrypto {t:15}-o file.x20 -m xsalsa20 -b ecdh-public.key -v ecdh-private.key "    +
                          "-e file.bin{t:0}\n"                                                                +
                          "\tcrypto {t:15}-o file.x20 -m xsalsa20 -9 public.cer -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file.x20 -m xsalsa20 -9 public.pem -e file.bin{t:0}\n"           +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                     +
                          "\tcrypto {t:15}-o file.bin -m xsalsa20 -d file.x20{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.bin -m xsalsa20 -s \"\" -h sha1 -d file.x20{t:0}\n"         +
                          "\tcrypto {t:15}-o file.bin -m xsalsa20 -v rsa-private.key -d file.x20{t:0}\n"      +
                          "\tcrypto {t:15}-o file.bin -m xsalsa20 -v elgamal-private.key -d file.x20{t:0}\n"  +
                          "\tcrypto {t:15}-o file.bin -m xsalsa20 -v naccache-private.key -d file.x20{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m xsalsa20 -b ecdh-public.key -v ecdh-private.key "    +
                          "-d file.x20{t:0}\n"                                                                +
                          "\tcrypto {t:15}-o file.bin -m xsalsa20 -9 private.pfx -d file.x20{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m xsalsa20 -v private.pem -d file.x20{t:0}\n"
                    );
                    break;

                case VMPC:
                    Messenger.Print
                    (
                          "\n\n {f:6}<VMPC>\n"                                                            +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                 +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -e file.bin{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -3 -e file.bin{t:0}\n"                      +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -s \"\" -h sha1 -e file.bin{t:0}\n"         +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -b rsa-public.key -e file.bin{t:0}\n"       +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -b elgamal-public.key -e file.bin{t:0}\n"   +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -b naccache-public.key -e file.bin{t:0}\n"  +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -b ecdh-public.key -v ecdh-private.key "    +
                          "-e file.bin{t:0}\n"                                                            +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -9 public.cer -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -9 public.pem -e file.bin{t:0}\n"           +
                          "\tcrypto {t:15}-o file.vmp -m vmpc -y 64 -l 64 -k 12345678 -i 87654321 "       +
                          "-e file.bin{t:0}\n"                                                            +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                 +
                          "\tcrypto {t:15}-o file.bin -m vmpc -d file.vmp{t:0}\n"                         +
                          "\tcrypto {t:15}-o file.bin -m vmpc -3 -d file.vmp{t:0}\n"                      +
                          "\tcrypto {t:15}-o file.bin -m vmpc -s \"\" -h sha1 -d file.vmp{t:0}\n"         +
                          "\tcrypto {t:15}-o file.bin -m vmpc -v rsa-private.key -d file.vmp{t:0}\n"      +
                          "\tcrypto {t:15}-o file.bin -m vmpc -v elgamal-private.key -d file.vmp{t:0}\n"  +
                          "\tcrypto {t:15}-o file.bin -m vmpc -v naccache-private.key -d file.vmp{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m vmpc -b ecdh-public.key -v ecdh-private.key "    +
                          "-d file.vmp{t:0}\n"                                                            +
                          "\tcrypto {t:15}-o file.bin -m vmpc -9 private.pfx -d file.vmp{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m vmpc -9 private.pem -d file.vmp{t:0}\n"          +
                          "\tcrypto {t:15}-o file.bin -m vmpc -y 64 -l 64 -k 12345678 -i 87654321 "       +
                          "-d file.vmp{t:0}\n"
                    );
                    break;

                case RC2:
                    Messenger.Print
                    (
                          "\n\n {f:6}<RC2>\n"                                                                       +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                           +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -e file.bin{t:0}\n"                                    +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -p \"my password\" -s \"my salt8\" -e file.bin{t:0}\n" +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -p file:\"my password file.txt\" -e file.bin{t:0}\n"   +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -s \"\" -h sha1 -e file.bin{t:0}\n"                    +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -b rsa-public.key -e file.bin{t:0}\n"                  +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -b elgamal-public.key -e file.bin{t:0}\n"              +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -b naccache-public.key -e file.bin{t:0}\n"             +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -b ecdh-public.key -v ecdh-private.key "               +
                          "-e file.bin{t:0}\n"                                                                      +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -9 public.cer -e file.bin{t:0}\n"                      +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -9 public.pem -e file.bin{t:0}\n"                      +
                          "\tcrypto {t:15}-o file.rc2 -m rc2 -y 64 -k 12345678 -i 87654321 -e file.bin{t:0}\n"      +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                           +
                          "\tcrypto {t:15}-o file.bin -m rc2 -d file.rc2{t:0}\n"                                    +
                          "\tcrypto {t:15}-o file.bin -m rc2 -p \"my password\" -s \"my salt8\" -d file.rc2{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m rc2 -p file:\"my password file.txt\" -d file.rc2{t:0}\n"   +
                          "\tcrypto {t:15}-o file.bin -m rc2 -s \"\" -h sha1 -d file.rc2{t:0}\n"                    +
                          "\tcrypto {t:15}-o file.bin -m rc2 -v rsa-private.key -d file.rc2{t:0}\n"                 +
                          "\tcrypto {t:15}-o file.bin -m rc2 -v elgamal-private.key -d file.rc2{t:0}\n"             +
                          "\tcrypto {t:15}-o file.bin -m rc2 -v naccache-private.key -d file.rc2{t:0}\n"            +
                          "\tcrypto {t:15}-o file.bin -m rc2 -b ecdh-public.key -v ecdh-private.key "               +
                          "-d file.rc2{t:0}\n"                                                                      +
                          "\tcrypto {t:15}-o file.bin -m rc2 -9 private.pfx -d file.rc2{t:0}\n"                     +
                          "\tcrypto {t:15}-o file.bin -m rc2 -9 private.pem -d file.rc2{t:0}\n"                     +
                          "\tcrypto {t:15}-o file.bin -m rc2 -y 64 -k 12345678 -i 87654321 -d file.rc2{t:0}\n"
                    );
                    break;

                case CAMELLIA:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , CAMELLIA
                              , CAMELLIA.Substring(0, 3).ToLower()
                              , CAMELLIA.ToLower()
                              , s3
                          )
                    );
                    break;

                case BLOWFISH:
                    Messenger.Print
                    (
                          string.Format(s4, BLOWFISH, "blf", BLOWFISH.ToLower(), s3)
                    );
                    break;

                case TWOFISH:
                    Messenger.Print
                    (
                          string.Format(s4, "2FISH", "2f", TWOFISH.ToLower(), s3)
                    );
                    break;

                case THREEFISH:
                    Messenger.Print
                    (
                          "\n\n {f:6}<3FISH>\n"                                                                      +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                            +
                          "\tcrypto {t:15}-o file.3f -m 3fish -e file.bin{t:0}\n"                                    +
                          "\tcrypto {t:15}-o file.3f -m 3fish -p \"my password\" -s \"my salt8\" -e file.bin{t:0}\n" +
                          "\tcrypto {t:15}-o file.3f -m 3fish -p file:\"my password file.txt\" -e file.bin{t:0}\n"   +
                          "\tcrypto {t:15}-o file.3f -m 3fish -s \"\" -h sha1 -e file.bin{t:0}\n"                    +
                          "\tcrypto {t:15}-o file.3f -m 3fish -b rsa-public.key -e file.bin{t:0}\n"                  +
                          "\tcrypto {t:15}-o file.3f -m 3fish -b elgamal-public.key -e file.bin{t:0}\n"              +
                          "\tcrypto {t:15}-o file.3f -m 3fish -b naccache-public.key -e file.bin{t:0}\n"             +
                          "\tcrypto {t:15}-o file.3f -m 3fish -b ecdh-public.key -v ecdh-private.key "               +
                          "-e file.bin{t:0}\n"                                                                       +
                          "\tcrypto {t:15}-o file.3f -m 3fish -9 public.cer -e file.bin{t:0}\n"                      +
                          "\tcrypto {t:15}-o file.3f -m 3fish -9 public.pem -e file.bin{t:0}\n"                      +
                          "\tcrypto {t:15}-o file.3f -m 3fish -k 12345678901234567890123456789012 "                  +
                          "-i 6543210987654321 -e file.bin{t:0}\n"                                                   +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                            +
                          "\tcrypto {t:15}-o file.bin -m 3fish -d file.3f{t:0}\n"                                    +
                          "\tcrypto {t:15}-o file.bin -m 3fish -p \"my password\" -s \"my salt8\" -d file.3f{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m 3fish -p file:\"my password file.txt\" -d file.3f{t:0}\n"   +
                          "\tcrypto {t:15}-o file.bin -m 3fish -s \"\" -h sha1 -d file.3f{t:0}\n"                    +
                          "\tcrypto {t:15}-o file.bin -m 3fish -v rsa-private.key -d file.3f{t:0}\n"                 +
                          "\tcrypto {t:15}-o file.bin -m 3fish -v elgamal-private.key -d file.3f{t:0}\n"             +
                          "\tcrypto {t:15}-o file.bin -m 3fish -v naccache-private.key -d file.3f{t:0}\n"            +
                          "\tcrypto {t:15}-o file.bin -m 3fish -b ecdh-public.key -v ecdh-private.key "              +
                          "-d file.3f{t:0}\n"                                                                        +
                          "\tcrypto {t:15}-o file.bin -m 3fish -9 private.pfx -d file.3f{t:0}\n"                     +
                          "\tcrypto {t:15}-o file.bin -m 3fish -9 private.pem -d file.3f{t:0}\n"                     +
                          "\tcrypto {t:15}-o file.bin -m 3fish -k 12345678901234567890123456789012 "                 +
                          "-i 6543210987654321 -d file.3f{t:0}\n"
                    );
                    break;

                case SERPENT:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , SERPENT
                              , SERPENT.Substring(0, 3).ToLower()
                              , SERPENT.ToLower()
                              , s3
                          )
                    );
                    break;

                case TNEPRES:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , TNEPRES
                              , TNEPRES.Substring(0, 3).ToLower()
                              , TNEPRES.ToLower()
                              , s3
                          )
                    );
                    break;

                case CAST5:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , CAST5
                              , "c5"
                              , CAST5.ToLower()
                              , s3
                          )
                    );
                    break;

                case CAST6:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , CAST6
                              , "c6"
                              , CAST6.ToLower()
                              , s3
                          )
                    );
                    break;

                case IDEA:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , IDEA
                              , IDEA.Substring(0, 3).ToLower()
                              , IDEA.ToLower()
                              , string.Empty
                          )
                    );
                    break;

                case NOEKEON:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , NOEKEON
                              , NOEKEON.Substring(0, 3).ToLower()
                              , NOEKEON.ToLower()
                              , string.Empty
                          )
                    );
                    break;

                case TEA:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , TEA
                              , TEA.ToLower()
                              , TEA.ToLower()
                              , string.Empty
                          )
                    );
                    break;

                case XTEA:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , XTEA
                              , XTEA.ToLower()
                              , XTEA.ToLower()
                              , string.Empty
                          )
                    );
                    break;

                case SEED:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , SEED
                              , SEED.ToLower()
                              , SEED.ToLower()
                              , string.Empty
                          )
                    );
                    break;

                case SKIPJACK:
                    Messenger.Print
                    (
                          string.Format
                          (
                                s4
                              , SKIPJACK
                              , "sj"
                              , SKIPJACK.ToLower()
                              , string.Empty
                          )
                    );
                    break;

                case GOST:
                    Messenger.Print
                    (
                         "\n\n {f:6}<GOST>\n"                                                             +
                         "\n {f:14}Encryption:{f:7}\n\n"                                                  +
                         "\tcrypto {t:15}-o file.gost -m gost -e file.bin{t:0}\n"                         +
                         "\tcrypto {t:15}-o file.gost -m gost -k 12345678901234567890123456789012 "       +
                         "-e file.bin{t:0}\n"                                                             +
                         "\tcrypto {t:15}-o file.gost -m gost -b rsa-public.key -e file.bin{t:0}\n"       +
                         "\tcrypto {t:15}-o file.gost -m gost -b elgamal-public.key -e file.bin{t:0}\n"   +
                         "\tcrypto {t:15}-o file.gost -m gost -b naccache-public.key -e file.bin{t:0}\n"  +
                         "\tcrypto {t:15}-o file.gost -m gost -b ecdh-public.key -v ecdh-private.key "    +
                         "-e file.bin{t:0}\n"                                                             +
                         "\tcrypto {t:15}-o file.gost -m gost -9 public.cer -e file.bin{t:0}\n"           +
                         "\tcrypto {t:15}-o file.gost -m gost -9 public.pem -e file.bin{t:0}\n"           +
                         "\tcrypto {t:15}-o file.gost -m gost -s \"\" -h sha1 -e file.bin{t:0}\n"         +
                         "\tcrypto {t:15}-o file.gost -m gost -p \"my password\" -s \"my salt8\" "        +
                         "-e file.bin{t:0}\n"                                                             +
                         "\tcrypto {t:15}-o file.gost -m gost -p file:\"my password file.txt\" "          +
                         "-e file.bin{t:0}\n"                                                             +
                         "\tcrypto {t:15}-o file.gost -m gost --gost-box iv -e file.bin{t:0}\n"           +
                         "\n {f:14}Decryption:{f:7}\n\n"                                                  +
                         "\tcrypto {t:15}-o file.bin -m gost -d file.gost{t:0}\n"                         +
                         "\tcrypto {t:15}-o file.bin -m gost -k 12345678901234567890123456789012 "        +
                         "-d file.gost{t:0}\n"                                                            +
                         "\tcrypto {t:15}-o file.bin -m gost -v rsa-private.key -d file.gost{t:0}\n"      +
                         "\tcrypto {t:15}-o file.bin -m gost -v elgamal-private.key -d file.gost{t:0}\n"  +
                         "\tcrypto {t:15}-o file.bin -m gost -v naccache-private.key -d file.gost{t:0}\n" +
                         "\tcrypto {t:15}-o file.bin -m gost -b ecdh-public.key -v ecdh-private.key "     +
                         "-d file.gost{t:0}\n"                                                            +
                         "\tcrypto {t:15}-o file.bin -m gost -9 private.pfx -d file.gost{t:0}\n"          +
                         "\tcrypto {t:15}-o file.bin -m gost -9 private.pem -d file.gost{t:0}\n"          +
                         "\tcrypto {t:15}-o file.bin -m gost -s \"\" -h sha1 -d file.gost{t:0}\n"         +
                         "\tcrypto {t:15}-o file.bin -m gost -p \"my password\" -s \"my salt8\" "         +
                         "-d file.gost{t:0}\n"                                                            +
                         "\tcrypto {t:15}-o file.bin -m gost -p file:\"my password file.txt\" "           +
                         "-d file.gost{t:0}\n"                                                            +
                         "\tcrypto {t:15}-o file.bin -m gost --gost-box iv -d file.gost{t:0}\n"
                    );
                    break;

                case RC5:
                    Messenger.Print
                    (
                         "\n\n {f:6}<RC5>\n"                                                                       +
                         "\n {f:14}Encryption:{f:7}\n\n"                                                           +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -e file.bin{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -e -4 -5 255 -e file.bin{t:0}\n"                       +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -b rsa-public.key -e file.bin{t:0}\n"                  +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -b elgamal-public.key -e file.bin{t:0}\n"              +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -b naccache-public.key -e file.bin{t:0}\n"             +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -b ecdh-public.key -v ecdh-private.key "               +
                         "-e file.bin{t:0}\n"                                                                      +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -9 public.cer -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -9 public.pem -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -k 1234567890123456 -e file.bin{t:0}\n"                +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -s \"\" -h sha1 -e file.bin{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -p \"my password\" -s \"my salt8\" -e file.bin{t:0}\n" +
                         "\tcrypto {t:15}-o file.rc5 -m rc5 -p file:\"my password file.txt\" -e file.bin{t:0}\n"   +
                         "\n {f:14}Decryption:{f:7}\n\n"                                                           +
                         "\tcrypto {t:15}-o file.bin -m rc5 -d file.rc5{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.bin -m rc5 -e -4 -5 255 -d file.rc5{t:0}\n"                       +
                         "\tcrypto {t:15}-o file.bin -m rc5 -v rsa-private.key -d file.rc5{t:0}\n"                 +
                         "\tcrypto {t:15}-o file.bin -m rc5 -v elgamal-private.key -d file.rc5{t:0}\n"             +
                         "\tcrypto {t:15}-o file.bin -m rc5 -v naccache-private.key -d file.rc5{t:0}\n"            +
                         "\tcrypto {t:15}-o file.bin -m rc5 -b ecdh-public.key -v ecdh-private.key "               +
                         "-d file.rc5{t:0}\n"                                                                      +
                         "\tcrypto {t:15}-o file.bin -m rc5 -9 private.pfx -d file.rc5{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m rc5 -9 private.pem -d file.rc5{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m rc5 -k 1234567890123456 -d file.rc5{t:0}\n"                +
                         "\tcrypto {t:15}-o file.bin -m rc5 -s \"\" -h sha1 -d file.rc5{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.bin -m rc5 -p \"my password\" -s \"my salt8\" -d file.rc5{t:0}\n" +
                         "\tcrypto {t:15}-o file.bin -m rc5 -p file:\"my password file.txt\" -d file.rc5{t:0}\n"
                    );
                    break;

                case RC6:
                    Messenger.Print
                    (
                         "\n\n {f:6}<RC6>\n" +
                         "\n {f:14}Encryption:{f:7}\n\n"                                                           +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -e file.bin{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -b rsa-public.key -e file.bin{t:0}\n"                  +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -b elgamal-public.key -e file.bin{t:0}\n"              +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -b naccache-public.key -e file.bin{t:0}\n"             +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -b ecdh-public.key -v ecdh-private.key "               +
                         "-e file.bin{t:0}\n"                                                                      +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -9 public.cer -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -9 public.pem -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -k 1234567890123456 -e file.bin{t:0}\n"                +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -s \"\" -h sha1 -e file.bin{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -p \"my password\" -s \"my salt8\" -e file.bin{t:0}\n" +
                         "\tcrypto {t:15}-o file.rc6 -m rc6 -p file:\"my password file.txt\" -e file.bin{t:0}\n"   +
                         "\n {f:14}Decryption:{f:7}\n\n"                                                           +
                         "\tcrypto {t:15}-o file.bin -m rc6 -d file.rc6{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.bin -m rc6 -v rsa-private.key -d file.rc6{t:0}\n"                 +
                         "\tcrypto {t:15}-o file.bin -m rc6 -v elgamal-private.key -d file.rc6{t:0}\n"             +
                         "\tcrypto {t:15}-o file.bin -m rc6 -v naccache-private.key -d file.rc6{t:0}\n"            +
                         "\tcrypto {t:15}-o file.bin -m rc6 -b ecdh-public.key -v ecdh-private.key "               +
                         "-d file.rc6{t:0}\n"                                                                      +
                         "\tcrypto {t:15}-o file.bin -m rc6 -9 private.pfx -d file.rc6{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m rc6 -9 private.pem -d file.rc6{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m rc6 -k 1234567890123456 -d file.rc6{t:0}\n"                +
                         "\tcrypto {t:15}-o file.bin -m rc6 -s \"\" -h sha1 -d file.rc6{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.bin -m rc6 -p \"my password\" -s \"my salt8\" -d file.rc6{t:0}\n" +
                         "\tcrypto {t:15}-o file.bin -m rc6 -p file:\"my password file.txt\" -d file.rc6{t:0}\n"
                    );
                    break;

                case RC4:
                    Messenger.Print
                    (
                         "\n\n {f:6}<RC4>\n"                                                                       +
                         "\n {f:14}Encryption:{f:7}\n\n"                                                           +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -e file.bin{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -b rsa-public.key -e file.bin{t:0}\n"                  +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -b elgamal-public.key -e file.bin{t:0}\n"              +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -b naccache-public.key -e file.bin{t:0}\n"             +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -b ecdh-public.key -v ecdh-private.key "               +
                         "-e file.bin{t:0}\n"                                                                      +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -9 public.cer -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -9 public.pem -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -y 128 -k 1234567890123456 -e file.bin{t:0}\n"         +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -s \"\" -h sha1 -e file.bin{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -p \"my password\" -s \"my salt8\" -e file.bin{t:0}\n" +
                         "\tcrypto {t:15}-o file.rc4 -m rc4 -p file:\"my password file.txt\" -e file.bin{t:0}\n"   +
                         "\n {f:14}Decryption:{f:7}\n\n"                                                           +
                         "\tcrypto {t:15}-o file.bin -m rc4 -d file.rc4{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.bin -m rc4 -v rsa-private.key -d file.rc4{t:0}\n"                 +
                         "\tcrypto {t:15}-o file.bin -m rc4 -v elgamal-private.key -d file.rc4{t:0}\n"             +
                         "\tcrypto {t:15}-o file.bin -m rc4 -v naccache-private.key -d file.rc4{t:0}\n"            +
                         "\tcrypto {t:15}-o file.bin -m rc4 -b ecdh-public.key -v ecdh-private.key "               +
                         "-d file.rc4{t:0}\n"                                                                      +
                         "\tcrypto {t:15}-o file.bin -m rc4 -9 private.pfx -d file.rc4{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m rc4 -9 private.pem -d file.rc4{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m rc4 -y 128 -k 1234567890123456 -d file.rc4{t:0}\n"         +
                         "\tcrypto {t:15}-o file.bin -m rc4 -s \"\" -h sha1 -d file.rc4{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.bin -m rc4 -p \"my password\" -s \"my salt8\" -d file.rc4{t:0}\n" +
                         "\tcrypto {t:15}-o file.bin -m rc4 -p file:\"my password file.txt\" -d file.rc4{t:0}\n"
                    );
                    break;

                case HC:
                    Messenger.Print
                    (
                         "\n\n {f:6}<HC>\n"                                                                      +
                         "\n {f:14}Encryption:{f:7}\n\n"                                                         +
                         "\tcrypto {t:15}-o file.hc -m hc -e file.bin{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.hc -m hc -b rsa-public.key -e file.bin{t:0}\n"                  +
                         "\tcrypto {t:15}-o file.hc -m hc -b elgamal-public.key -e file.bin{t:0}\n"              +
                         "\tcrypto {t:15}-o file.hc -m hc -b naccache-public.key -e file.bin{t:0}\n"             +
                         "\tcrypto {t:15}-o file.hc -m hc -b ecdh-public.key -v ecdh-private.key "               +
                         "-e file.bin{t:0}\n"                                                                    +
                         "\tcrypto {t:15}-o file.hc -m hc -9 public.cer -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.hc -m hc -9 public.pem -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.hc -m hc -y 128 -k 1234567890123456 -e file.bin{t:0}\n"         +
                         "\tcrypto {t:15}-o file.hc -m hc -s \"\" -h sha1 -e file.bin{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.hc -m hc -p \"my password\" -s \"my salt8\" -e file.bin{t:0}\n" +
                         "\tcrypto {t:15}-o file.hc -m hc -p file:\"my password file.txt\" -e file.bin{t:0}\n"   +
                         "\n {f:14}Decryption:{f:7}\n\n"                                                         +
                         "\tcrypto {t:15}-o file.bin -m hc -d file.hc{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.bin -m hc -v rsa-private.key -d file.hc{t:0}\n"                 +
                         "\tcrypto {t:15}-o file.bin -m hc -v elgamal-private.key -d file.hc{t:0}\n"             +
                         "\tcrypto {t:15}-o file.bin -m hc -v naccache-private.key -d file.hc{t:0}\n"            +
                         "\tcrypto {t:15}-o file.bin -m hc -b ecdh-public.key -v ecdh-private.key "              +
                         "-d file.hc{t:0}\n"                                                                     +
                         "\tcrypto {t:15}-o file.bin -m hc -9 private.pfx -d file.hc{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m hc -9 private.pem -d file.hc{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m hc -y 128 -k 1234567890123456 -d file.hc{t:0}\n"         +
                         "\tcrypto {t:15}-o file.bin -m hc -s \"\" -h sha1 -d file.hc{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.bin -m hc -p \"my password\" -s \"my salt8\" -d file.hc{t:0}\n" +
                         "\tcrypto {t:15}-o file.bin -m hc -p file:\"my password file.txt\" -d file.hc{t:0}\n"
                    );
                    break;

                case ISAAC:
                    Messenger.Print
                    (
                         "\n\n {f:6}<ISAAC>\n"                                                                       +
                         "\n {f:14}Encryption:{f:7}\n\n"                                                             +
                         "\tcrypto {t:15}-o file.isa -m isaac -e file.bin{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.isa -m isaac -b rsa-public.key -e file.bin{t:0}\n"                  +
                         "\tcrypto {t:15}-o file.isa -m isaac -b elgamal-public.key -e file.bin{t:0}\n"              +
                         "\tcrypto {t:15}-o file.isa -m isaac -b naccache-public.key -e file.bin{t:0}\n"             +
                         "\tcrypto {t:15}-o file.isa -m isaac -b ecdh-public.key -v ecdh-private.key "               +
                         "-e file.bin{t:0}\n"                                                                        +
                         "\tcrypto {t:15}-o file.isa -m isaac -9 public.cer -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.isa -m isaac -9 public.pem -e file.bin{t:0}\n"                      +
                         "\tcrypto {t:15}-o file.isa -m isaac -y 8192 -e file.bin{t:0}\n"                            +
                         "\tcrypto {t:15}-o file.isa -m isaac -s \"\" -h sha1 -e file.bin{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.isa -m isaac -p \"my password\" -s \"my salt8\" -e file.bin{t:0}\n" +
                         "\tcrypto {t:15}-o file.isa -m isaac -p file:\"my password file.txt\" -e file.bin{t:0}\n"   +
                         "\n {f:14}Decryption:{f:7}\n\n"                                                             +
                         "\tcrypto {t:15}-o file.bin -m isaac -d file.isa{t:0}\n"                                    +
                         "\tcrypto {t:15}-o file.bin -m isaac -v rsa-private.key -d file.isa{t:0}\n"                 +
                         "\tcrypto {t:15}-o file.bin -m isaac -v elgamal-private.key -d file.isa{t:0}\n"             +
                         "\tcrypto {t:15}-o file.bin -m isaac -v naccache-private.key -d file.isa{t:0}\n"            +
                         "\tcrypto {t:15}-o file.bin -m isaac -b ecdh-public.key -v ecdh-private.key "               +
                         "-d file.isa{t:0}\n"                                                                        +
                         "\tcrypto {t:15}-o file.bin -m isaac -9 private.pfx -d file.isa{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m isaac -9 private.pem -d file.isa{t:0}\n"                     +
                         "\tcrypto {t:15}-o file.bin -m isaac -y 8192 -d file.isa{t:0}\n"                            +
                         "\tcrypto {t:15}-o file.bin -m isaac -s \"\" -h sha1 -d file.isa{t:0}\n"                    +
                         "\tcrypto {t:15}-o file.bin -m isaac -p \"my password\" -s \"my salt8\" -d file.isa{t:0}\n" +
                         "\tcrypto {t:15}-o file.bin -m isaac -p file:\"my password file.txt\" -d file.isa{t:0}\n"
                    );
                    break;

                case ECIES:
                    Messenger.Print
                    (
                          "\n\n {f:6}<ECIES>\n"                                                                 +
                          "\n {f:14}Key pair generation:{f:7}\n\n"                                              +
                          "\tcrypto {t:15}-m ecies -g -b public.key -v private.key{t:0}\n"                      +
                          "\tcrypto {t:15}-m ecies -g -b public.key -v private.key --curve-store x962 "         +
                          "--curve prime256v1{t:0}\n"                                                           +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                       +
                          "\tcrypto {t:15}-o file.ies -m ecies -b public.key -v private.key -e file.bin{t:0}\n" +
                          "\tcrypto {t:15}-o file.ies -m ecies -b public.key -v private.key -h sha1 "           +
                          "--ies-cipher rijndael -y 128 -l 128 -e file.bin{t:0}\n"                              +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                       +
                          "\tcrypto {t:15}-o file.bin -m ecies -b public.key -v private.key -e file.ies{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m ecies -b public.key -v private.key -h sha1 "           +
                          "--ies-cipher rijndael -y 128 -l 128 -e file.ies{t:0}\n"
                    );
                    break;

                case DLIES:
                    Messenger.Print
                    (
                          "\n\n {f:6}<DLIES>\n"                                                                  +
                          "\n {f:14}Key pair generation:{f:7}\n\n"                                               +
                          "\tcrypto {t:15}-m dlies -g -b public.key -v private.key{t:0}\n"                       +
                          "\tcrypto {t:15}-m dlies -g -b public.key -v private.key -y 1024 --certainty 8{t:0}\n" +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                        +
                          "\tcrypto {t:15}-o file.ies -m dlies -b public.key -v private.key -e file.bin{t:0}\n"  +
                          "\tcrypto {t:15}-o file.ies -m dlies -b public.key -v private.key -h sha1 "            +
                          "--ies-cipher rijndael -y 128 -l 128 -e file.bin{t:0}\n"                               +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                        +
                          "\tcrypto {t:15}-o file.bin -m dlies -b public.key -v private.key -e file.ies{t:0}\n"  +
                          "\tcrypto {t:15}-o file.bin -m dlies -b public.key -v private.key -h sha1 "            +
                          "--ies-cipher rijndael -y 128 -l 128 -e file.ies{t:0}\n"
                    );
                    break;

                case RSA:
                    Messenger.Print
                    (
                          "\n\n {f:6}<RSA>\n"                                                                      +
                          "\n {f:14}Key pair generation:{f:7}\n\n"                                                 +
                          "\tcrypto {t:15}-m rsa -g -b public.key -v private.key{t:0}\n"                           +
                          "\tcrypto {t:15}-m rsa -g -b public.key -v private.key -y 2048 -6 128{t:0}\n"            +
                          "\tcrypto {t:15}-m rsa -g -f xml -b public-key.xml -v private-key.xml{t:0}\n"            +
                          "\tcrypto {t:15}-m rsa -g --rsa-bouncy-castle -b public.key -v private.key{t:0}\n"       +
                          "\tcrypto {t:15}-m rsa -g -y 2048 --rsa-bouncy-castle --certainty 20 "                   +
                          "--public-exponent 17 -b public.key -v private.key{t:0}\n"                               +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                          +
                          "\tcrypto {t:15}-o file.rsa -m rsa -b public.key -e file.bin{t:0}\n"                     +
                          "\tcrypto {t:15}-o file.rsa -m rsa -b public-key.xml -a -e file.bin{t:0}\n"              +
                          "\tcrypto {t:15}-o file.rsa -m rsa -u -b pgp-public.key -e file.bin{t:0}\n"              +
                          "\tcrypto {t:15}-o file.rsa -m rsa -9 file.pem -e file.bin{t:0}\n"                       +
                          "\tcrypto {t:15}-o file.rsa -m rsa -9 file.cer -e -a file.bin{t:0}\n"                    +
                          "\tcrypto {t:15}-o file.rsa -m rsa -0 \"my certificate common-name\" -e file.bin{t:0}\n" +
                          "\tcrypto {t:15}-o file.rsa -m rsa --rsa-bouncy-castle -b public.key "                   +
                          "-e file.bin{t:0}\n"                                                                     +
                          "\tcrypto {t:15}-o file.rsa -m rsa --signature file.sig -v private.key "                 +
                          "-e file.bin{t:0}\n"                                                                     +
                          "\tcrypto {t:15}-o file.rsa -m rsa --signature pss file.sig -h sha1 "                    +
                          "-v private.key -e file.bin{t:0}\n"                                                      +
                          "\tcrypto {t:15}-o file.rsa -m rsa --rsa-bouncy-castle --signature file.sig -a "         +
                          "-h sha1 -v private.key -e file.bin{t:0}\n"                                              +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                          +
                          "\tcrypto {t:15}-o file.bin -m rsa -b private.key -d file.rsa{t:0}\n"                    +
                          "\tcrypto {t:15}-o file.bin -m rsa -v private-key.xml -a -d file.rsa{t:0}\n"             +
                          "\tcrypto {t:15}-o file.bin -m rsa -u -v pgp-private.key -d file.rsa{t:0}\n"             +
                          "\tcrypto {t:15}-o file.bin -m rsa -9 file.pem -d file.rsa{t:0}\n"                       +
                          "\tcrypto {t:15}-o file.bin -m rsa -9 file.pfx -p \"my password\" -a -d file.rsa{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m rsa --rsa-bouncy-castle -b private.key "                  +
                          "-d file.rsa{t:0}\n"                                                                     +
                          "\tcrypto {t:15}-o file.bin -m rsa --signature file.sig -v private.key "                 +
                          "-d file.rsa{t:0}\n"                                                                     +
                          "\tcrypto {t:15}-o file.bin -m rsa --signature pss file.sig -h sha1 "                    +
                          "-v private.key -d file.rsa{t:0}\n"                                                      +
                          "\tcrypto {t:15}-o file.bin -m rsa --rsa-bouncy-castle --signature file.sig -a "         +
                          "-h sha1 -v private.key -d file.rsa{t:0}\n"
                    );
                    break;

                case PGP:
                    Messenger.Print
                    (
                          "\n\n {f:6}<PGP>\n"                                                                      +
                          "\n {f:14}Key pair generation:{f:7}\n\n"                                                 +
                          "\tcrypto {t:15}-m pgp -g -b public.key -v private.key -y 2048 --pgp-sha1{t:0}\n"        +
                          "\tcrypto {t:15}-m pgp -g -f armored -b public.asc -v private.asc -q 2fish{t:0}\n"       +
                          "\tcrypto {t:15}-m pgp -g -b public.key -v private.key "                                 +
                          "--pgp-id \"My Name <my@email.com>\"{t:0}\n"                                             +
                          "\tcrypto {t:15}-m pgp -g -y 2048 --rsa-bouncy-castle --public-exponent 17 "             +
                          "--certainty 80 -b public.key -v private.key{t:0}\n"                                     +
                          "\tcrypto {t:15}-m pgp --pgp-algorithm elgamal -g -b public.key -v private.key{t:0}\n"   +
                          "\tcrypto {t:15}-m pgp --pgp-algorithm elgamal --pgp-master ecdsa "                      +
                          "--curve-store x962 --curve prime256v1 -g -b public.key "                                +
                          "-v private.key{t:0}\n"                                                                  +
                          "\tcrypto {t:15}-m pgp --pgp-algorithm elgamal --pgp-master rsa -g "                     +
                          "-b public.key -v private.key{t:0}\n"                                                    +
                          "\tcrypto {t:15}-m pgp --pgp-algorithm ecdh -y 256 -g -b public.key "                    +
                          "-v private.key{t:0}\n"                                                                  +
                          "\tcrypto {t:15}-m pgp --pgp-algorithm ecdh -y 521 -g -b public.key "                    +
                          "-v private.key --curve-store x962 --curve prime256v1{t:0}\n"                            +
                          "\tcrypto {t:15}-m pgp --pgp-algorithm ecdh -y 192 --pgp-master dsa -g "                 +
                          "-b public.key -v private.key{t:0}\n"                                                    +
                          "\tcrypto {t:15}-m pgp --pgp-algorithm ecdh --curve prime256v1 "                         +
                          "--curve sect163r2 -g -b public.key -v private.key{t:0}\n"                               +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                          +
                          "\tcrypto {t:15}-o file.pgp -m pgp -b public.key -q safer -e file.bin{t:0}\n"            +
                          "\tcrypto {t:15}-o file.pgp -m pgp -b public.key --pgp-compress zlib "                   +
                          "-e file.bin{t:0}\n"                                                                     +
                          "\tcrypto {t:15}-o file.pgp -m pgp -f armored -b public.asc -e file.bin{t:0}\n"          +
                          "\tcrypto {t:15}-o file.pgp -m pgp -u -b rsa-public.key -e file.bin{t:0}\n"              +
                          "\tcrypto {t:15}-o file.pgp -m pgp --pgp-algorithm elgamal -u "                          +
                          "-b elgamal-public.key -e file.bin{t:0}\n"                                               +
                          "\tcrypto {t:15}-o file.pgp -m pgp -9 file.pem -e file.bin{t:0}\n"                       +
                          "\tcrypto {t:15}-o file.pgp -m pgp -9 file.cer -e file.bin{t:0}\n"                       +
                          "\tcrypto {t:15}-o file.pgp -m pgp -0 \"my certificate common-name\" -e file.bin{t:0}\n" +
                          "\tcrypto {t:15}-o file.pgp -m pgp --pgp-signature -u -v rsa-private.key "               +
                          "-e file.bin{t:0}\n"                                                                     +
                          "\tcrypto {t:15}-o file.pgp -m pgp --pgp-signature -9 file.pfx -e file.bin{t:0}\n"       +
                          "\tcrypto {t:15}-o file.pgp -m pgp --pgp-signature -9 public.pem "                       +
                          "-9 private.pem -e file.bin{t:0}\n"                                                      +
                          "\tcrypto {t:15}-o file.pgp -m pgp --pgp-signature -9 private: private.pem "             +
                          "-9 public: public.pem -e file.bin{t:0}\n"                                               +
                          "\tcrypto {t:15}-o file.pgp -m pgp --pgp-signature -b public.key "                       +
                          "-v private.key -e file.bin{t:0}\n"                                                      +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                          +
                          "\tcrypto {t:15}-o file.bin -m pgp -v private.key -d file.pgp{t:0}\n"                    +
                          "\tcrypto {t:15}-o file.bin -m pgp -v private.asc -d file.pgp{t:0}\n"                    +
                          "\tcrypto {t:15}-o file.bin -m pgp -u -v rsa-private.key -d file.pgp{t:0}\n"             +
                          "\tcrypto {t:15}-o file.bin -m pgp --pgp-algorithm elgamal -u "                          +
                          "-b elgamal-public.key -v elgamal-private.key -d file.pgp{t:0}\n"                        +
                          "\tcrypto {t:15}-o file.bin -m pgp -9 file.pem -d file.pgp{t:0}\n"                       +
                          "\tcrypto {t:15}-o file.bin -m pgp -9 file.pfx -p \"my password\" -d file.pgp{t:0}\n"    +
                          "\tcrypto {t:15}-o file.bin -m pgp --pgp-signature -u -v rsa-private.key "               +
                          "-d file.pgp{t:0}\n"                                                                     +
                          "\tcrypto {t:15}-o file.bin -m pgp --pgp-signature -9 file.pfx -d file.pgp{t:0}\n"       +
                          "\tcrypto {t:15}-o file.bin -m pgp --pgp-signature -9 private.pem "                      +
                          "-9 public.pem -d file.pgp{t:0}\n"                                                       +
                          "\tcrypto {t:15}-o file.bin -m pgp --pgp-signature -9 public: public.pem "               +
                          "-9 private: private.pem -d file.pgp{t:0}\n"                                             +
                          "\tcrypto {t:15}-o file.bin -m pgp --pgp-signature -v private.key "                      +
                          "-b public.key -d file.pgp{t:0}\n"
                    );
                    break;

                case ELGAMAL:
                    Messenger.Print
                    (
                          "\n\n {f:6}<ELGAMAL>\n"                                                              +
                          "\n {f:14}Key pair generation:{f:7}\n\n"                                             +
                          "\tcrypto {t:15}-m elgamal -g -b public.key -v private.key{t:0}\n"                   +
                          "\tcrypto {t:15}-m elgamal -g -b public.key -v private.key -y 1024{t:0}\n"           +
                          "\tcrypto {t:15}-m elgamal -g --certainty 80 -b public.key "                         +
                          "-v private.key{t:0}\n"                                                              +
                          "\n {f:14}Encryption:{f:7}\n\n"                                                      +
                          "\tcrypto {t:15}-o file.elg -m elgamal -b public.key -e file.bin{t:0}\n"             +
                          "\tcrypto {t:15}-o file.elg -m elgamal -b public.key -a -e file.bin{t:0}\n"          +
                          "\tcrypto {t:15}-o file.elg -m elgamal -b public.key -a -h sha1 -e file.bin{t:0}\n"  +
                          "\tcrypto {t:15}-o file.elg -m elgamal -u -b pgp-public.key -e file.bin{t:0}\n"      +
                          "\tcrypto {t:15}-o file.elg -m elgamal --signature file.sig -h sha1 "                +
                          "-b public.key -e file.bin{t:0}\n"                                                   +
                          "\n {f:14}Decryption:{f:7}\n\n"                                                      +
                          "\tcrypto {t:15}-o file.bin -m elgamal -v private.key -d file.elg{t:0}\n"            +
                          "\tcrypto {t:15}-o file.bin -m elgamal -v private.key -a -d file.elg{t:0}\n"         +
                          "\tcrypto {t:15}-o file.bin -m elgamal -v private.key -a -h sha1 -d file.elg{t:0}\n" +
                          "\tcrypto {t:15}-o file.bin -m elgamal -u -v pgp-private.key -d file.elg{t:0}\n"     +
                          "\tcrypto {t:15}-o file.bin -m elgamal --signature file.sig -h sha1 "                +
                          "-v private.key -d file.elg{t:0}\n"
                    );
                    break;

                case NACCACHE:
                    Messenger.Print
                    (
                          "\n\n {f:6}<NACCACHE>\n"                                                    +
                          "\n {f:14}Key pair generation:{f:7}\n\n"                                    +
                          "\tcrypto {t:15}-m naccache -g -b public.key -v private.key{t:0}\n"         +
                          "\tcrypto {t:15}-m naccache -g -b public.key -v private.key -y 1024{t:0}\n" +
                          "\tcrypto {t:15}-m naccache -g -y 2048 --certainty 12 --small-primes 60 "   +
                          "-b public.key -v private.key{t:0}\n"                                       +
                          "\n {f:14}Encryption:{f:7}\n\n"                                             +
                          "\tcrypto {t:15}-o file.nac -m naccache -b public.key -e file.bin{t:0}\n"   +
                          "\tcrypto {t:15}-o file.nac -m naccache --signature file.sig "              +
                          "-b public.key -e file.bin{t:0}\n"                                          +
                          "\n {f:14}Decryption:{f:7}\n\n"                                             +
                          "\tcrypto {t:15}-o file.bin -m naccache -v private.key -d file.nac{t:0}\n"  +
                          "\tcrypto {t:15}-o file.bin -m naccache --signature file.sig "              +
                          "-v private.key -d file.nac{t:0}\n"
                    );
                    break;

                case ECDH:
                    Messenger.Print
                    (
                          "\n\n {f:6}<ECDH>\n"                                                                  +
                          "\n {f:14}Key pair generation:{f:7}\n\n"                                              +
                          "\tcrypto {t:15}-m ecdh -g -y 256 -b public.key -v private.key{t:0}\n"                +
                          "\tcrypto {t:15}-m ecdh -g -y 521 --certainty 80 -b public.key -v private.key{t:0}\n" +
                          "\tcrypto {t:15}-m ecdh --curve-store x962 --curve prime256v1 -g -b public.key "      +
                          "-v private.key{t:0}\n"                                                               +
                          "\n {f:14}Encryption and decryption:{f:7}\n\n"                                        +
                          "\tSee {t:8}any example of all symmetric ciphers, Pgp, and Ecies.{t:0}\n"
                    );
                    break;

                default:
                    throw new Exception("There are no examples to the specified mode!");
            }
        }

        //----------------------------------------------------------------------------------

        private static void ShowInputNotes ()
        {
            Program.ShowBanner();
            Messenger.Print
            (
                  "\n {f:14}>{t:3,f:7} The parameter \"file:\", at the beginning of the modifier --password, allows "    +
                  "to obtain the complete text of a file as password.{t:0}"                                              +
                  "\n {f:14}>{t:3,f:7} The parameter \"batch:\", at the beginning of the input file, processes the "     +
                  "input data paths as batch files. The paths must be separated by line feed "                           +
                  "or semicolon unless otherwise indicated.{t:0}"                                                        +
                  "\n {f:14}>{t:3,f:7} The semicolon character is the path delimiter unless otherwise indicated.{t:0}"   +
                  "\n {f:14}>{t:3,f:7} The parameter \"public:\" or \"private:\", at the beginning of the modifier "     +
                  "--x509-file or --x509-store specifies the certificate type, otherwise they will be used in order of " +
                  "occurrence.{t:0}\n"
            );
        }

        //----------------------------------------------------------------------------------

        private static string CheckArg 
        (
              string[] args
            , int      index
            , bool     strict = true
            , short    minlen = 1
            , bool     trim   = true
            , string   emsg   = null
        ){
            if (index < args.Length)
            {
                string s = trim ? args[index].Trim() : args[index];

                if (s.Length >= minlen)
                {
                    if (s.ToLower() == MOD_LONG_HELP && index - 1 > -1)
                        Program.ShowHelp(trim ? args[--index].Trim() : args[--index]);

                    else if (!strict || s.Length < 1 || s[0] != '-')
                        return s;
                }
            }

            throw new Exception(string.IsNullOrEmpty(emsg) ? MSG_MALFORMED_CMD_LINE : emsg);
        }

        //----------------------------------------------------------------------------------

        private static string CheckArg 
        (
              string[] args
            , int      index
            , bool     strict
            , short    minlen
            , string   emsg
        ){
            return Program.CheckArg(args, index, strict, minlen, true, emsg);
        }

        //----------------------------------------------------------------------------------

        private static string CheckArg (string[] args, int index, bool strict, string emsg)
        {
            return Program.CheckArg(args, index, strict, 1, emsg);
        }

        //----------------------------------------------------------------------------------

        private static string CheckArg (string[] args, int index, short minlen, string emsg)
        {
            return Program.CheckArg(args, index, true, minlen, emsg);
        }

        //----------------------------------------------------------------------------------

        private static string CheckArg (string[] args, int index, string emsg)
        {
            return Program.CheckArg(args, index, true, emsg);
        }

        //----------------------------------------------------------------------------------

        private static void AddCertificate (string[] args, ref int index, bool store)
        {
            string s = Program.CheckArg(args, ++index, false);
            byte   k = 0;
            string a = "public:";
            string b = "private:";
            int    i;

            if (s.Equals(a, StringComparison.InvariantCultureIgnoreCase))
            {
                s = Program.CheckArg(args, ++index, false);
                k = 1;
            }

            else if (s.Equals(b, StringComparison.InvariantCultureIgnoreCase))
            {
                s = Program.CheckArg(args, ++index, false);
                k = 2;
            }

            else if ((i = s.IndexOf(a, StringComparison.InvariantCultureIgnoreCase)) > -1)
            {
                s = s.Substring(i + a.Length);
                k = 1;
            }

            else if ((i = s.IndexOf(b, StringComparison.InvariantCultureIgnoreCase)) > -1)
            {
                s = s.Substring(i + b.Length);
                k = 2;
            }

            if ((i = _cer.Count) > 0) while (--i > -1)
            {
                AbstractCertificate t = _cer[i];

                if (t.type != 0 && t.type == k)
                {
                    t.target = s;
                    t.store  = store;
                    _cer[i]  = t;

                    return;
                }
            }

            if (_cer.Count > 1)
                _cer.RemoveAt(0);

            _cer.Add(AbstractCertificate.Create(s, store, k));
        }

        //----------------------------------------------------------------------------------

        static void Main (string[] args)
        {
            int l = args.Length;

            if (l < 1)
                Program.ShowHelp();

            else
            {
                AsymmetricKeyParameter  apbk = null;
                AsymmetricKeyParameter  apvk = null;
                Encoding                tenc = _encoding;
                List<string>            list = new List<string>();
                int                     iaux = 0;
                short                   naux = 0;
                bool                    baux = false;
                bool                    caux = false;
                bool                    daux = false;
                string                  saux = string.Empty;
                string                  emsg = string.Empty;
                string                  ifn  = string.Empty;
                string                  ofn  = string.Empty;
                string                  path = string.Empty;
                byte[]                  key  = null;
                string[]                ifp, ofp;

                _sk.key = _sk.iv = null;

                try
                {
                    for (int i = 0; i < l; ++i)
                    {
                        switch (args[i].ToLower())
                        {
                            case "-e":
                            case "--encrypt-encode":
                                _job = CryptoJob.ENCRYPT;
                                break;

                            case "-d":
                            case "--decrypt-decode":
                                _job = CryptoJob.DECRYPT;
                                break;

                            case "-2":
                            case "--b32-hex":
                                _b32hex = true;
                                break;

                            case "-8":
                            case "--no-rfc4648":
                                _rfc4648 = false;
                                break;

                            case "-1":
                            case "--base-code":
                                _code = Program.CheckArg(args, ++i, false, 2, MSG_INVALID_CODE);
                                break;

                            case "-6":
                            case "--base-line-wrap":
                                if (!Turn.ToInt16(Program.CheckArg(args, ++i), ref _charsperline) || _charsperline < 0 || _charsperline > 256)
                                    throw new Exception("The base line wrap can not be less than 0 or greater than 256!");

                                break;

                            case "-x":
                            case "--max-buffer-size":
                                if (!Turn.ToInt32(Program.CheckArg(args, ++i, MSG_INVALID_BUFFER_SIZE), ref _buffersize) || _buffersize < 1)
                                    throw new Exception("The buffer size can not be less than 1!");

                                break;

                            case "-o":
                            case "--output":
                                ofn = Program.CheckArg(args, ++i, false, 0);
                                break;

                            case MOD_SHORT_KEY_SIZE:
                            case MOD_LONG_KEY_SIZE:
                                if (!Turn.ToInt16(Program.CheckArg(args, ++i, MSG_INVALID_KEY_SIZE), ref _keysize))
                                    throw new Exception(MSG_INVALID_KEY_SIZE);

                                break;

                            case "-l":
                            case "--block-size":
                                if (!Turn.ToInt16(Program.CheckArg(args, ++i, MSG_INVALID_BLOCK_SIZE), ref _blocksize))
                                    throw new Exception(MSG_INVALID_BLOCK_SIZE);

                                break;

                            case "-z":
                            case "--feedback-size":
                                if (!Turn.ToInt16(Program.CheckArg(args, ++i, MSG_INVALID_FEEDBACK_SIZE), ref _feedbacksize))
                                    throw new Exception(MSG_INVALID_FEEDBACK_SIZE);

                                break;

                            case MOD_SHORT_MODE:
                            case MOD_LONG_MODE:
                                _mode = Program.CheckArg(args, ++i).ToUpper();
                                break;

                            case "-p":
                            case "--password":
                                if (string.IsNullOrEmpty(_password) || !_export)
                                {
                                    _password = Program.CheckArg(args, ++i, false, 0, false);
                                    saux      = "file:";

                                    if (_password.Equals(saux, StringComparison.InvariantCultureIgnoreCase))
                                        _password = File.ReadAllText(Program.CheckArg(args, ++i, false));

                                    else if ((iaux = _password.IndexOf(saux, StringComparison.InvariantCultureIgnoreCase)) > -1)
                                        _password = File.ReadAllText(_password.Substring(iaux + saux.Length));
                                }

                                else _export_pwd = Program.CheckArg(args, ++i, false, 0, false);
                                break;

                            case "-s":
                            case "--salt":
                                _salt        = Program.CheckArg(args, ++i, false, 0, false);
                                _saltleaking = true;
                                break;

                            case "-k":
                            case "--key":
                                _key = Program.CheckArg(args, ++i, false, 0, false);
                                break;

                            case "-i":
                            case "--initial-vector":
                                _iv = Program.CheckArg(args, ++i, false, 0, false);
                                break;

                            case "-t":  
                            case "--iterations":
                                if (!Turn.ToInt32(Program.CheckArg(args, ++i), ref _iterations) || _iterations < 1)
                                    throw new Exception("The iterations can not be less than 1!");

                                break;

                            case "-c":
                            case "--cipher-mode":
                                switch (Program.CheckArg(args, ++i).ToUpper())
                                {
                                    case "CBC":
                                        _ciphermode = CipherMode.CBC;
                                        break;
                                        
                                    case "CTS":
                                        _ciphermode = CipherMode.CTS;
                                        break;                                        

                                    case "ECB":
                                        _ciphermode = CipherMode.ECB;
                                        break;

                                    case "CFB":
                                        _ciphermode = CipherMode.CFB;
                                        break;

                                    case "OFB":
                                        _ciphermode = CipherMode.OFB;
                                        break;

                                    default:
                                        throw new Exception(MSG_INVALID_CIPHER_MODE);
                                }
                                break;

                            case "-n":
                            case "--padding":
                                daux = true;
                                switch (Program.CheckArg(args, ++i).ToUpper())
                                {
                                    case "X923":
                                        _padding = CryptoPadding.X923;
                                        break;

                                    case "ISO10126":
                                        _padding = CryptoPadding.ISO10126;
                                        break;

                                    case "ISO7816D4":
                                        _padding = CryptoPadding.ISO7816D4;
                                        break;

                                    case "PKCS7":
                                        _padding = CryptoPadding.PKCS7;
                                        break;

                                    case "PKCS1":
                                        _padding = CryptoPadding.PKCS1;
                                        break;

                                    case "ZEROS":
                                        _padding = CryptoPadding.Zeros;
                                        break;

                                    case "TBC":
                                        _padding = CryptoPadding.TBC;
                                        break;

                                    case "ISO9796D1":
                                        _padding = CryptoPadding.ISO9796D1;
                                        break;

                                    default:
                                        throw new Exception(MSG_INVALID_PADDING_MODE);
                                }
                                break;

                            case MOD_SHORT_HASH:
                            case MOD_LONG_HASH:
                                _hash = Program.CheckArg(args, ++i).ToUpper();
                                break;

                            case "-r":
                            case "--random-gen":
                                _random = true;
                                break;

                            case "-g":
                            case "--key-pair-gen":
                                _generator = true;
                                break;

                            case "-b":
                            case "--public-key":
                                if (string.IsNullOrEmpty(_public_key) || !_export)
                                     _public_key = Program.CheckArg(args, ++i, false, MSG_INVALID_PUBLIC_KEY);

                                else _export_pbk = Program.CheckArg(args, ++i, false, MSG_INVALID_PUBLIC_KEY); 
                                break;

                            case "-v":
                            case "--private-key":
                                if (string.IsNullOrEmpty(_private_key) || !_export)
                                     _private_key = Program.CheckArg(args, ++i, false, MSG_INVALID_PRIVATE_KEY);

                                else _export_pvk  = Program.CheckArg(args, ++i, false, MSG_INVALID_PRIVATE_KEY);
                                break;

                            case "-a":
                            case "--oaep":
                                _padding = CryptoPadding.OAEP;
                                daux     = true;
                                break;

                            case "-9": 
                            case "--x509-file":
                                Program.AddCertificate(args, ref i, false);
                                break;

                            case "-0":
                            case "--x509-store":
                                Program.AddCertificate(args, ref i, true);
                                break;

                            case "-f":
                            case "--format":
                                switch (Program.CheckArg(args, ++i).ToUpper())
                                {
                                    case "XML":
                                        _format = CryptoFormat.XML;
                                        break;
                                        
                                    case B64:
                                        _format = CryptoFormat.BASE64;
                                        break;

                                    case "ARMORED":
                                        _format = CryptoFormat.ARMORED;
                                        break;

                                    default:
                                        throw new Exception("Invalid format!");
                                }

                                break;
                            
                            case "q":
                            case "--pgp-cipher":
                                switch (Program.CheckArg(args, ++i).ToUpper())
                                {
                                    case "AES128":
                                        _ska = SymmetricKeyAlgorithmTag.Aes128;
                                        break;

                                    case "AES192":
                                        _ska = SymmetricKeyAlgorithmTag.Aes192;
                                        break;

                                    case "AES256":
                                        _ska = SymmetricKeyAlgorithmTag.Aes256;
                                        break;

                                    case BLOWFISH:
                                        _ska = SymmetricKeyAlgorithmTag.Blowfish;
                                        break;

                                    case CAST5:
                                        _ska = SymmetricKeyAlgorithmTag.Cast5;
                                        break;

                                    case DES:
                                        _ska = SymmetricKeyAlgorithmTag.Des;
                                        break;

                                    case IDEA:
                                        _ska = SymmetricKeyAlgorithmTag.Idea;
                                        break;

                                    case "SAFER":
                                        _ska = SymmetricKeyAlgorithmTag.Safer;
                                        break;

                                    case TDES:
                                        _ska = SymmetricKeyAlgorithmTag.TripleDes;
                                        break;

                                    case TWOFISH:
                                        _ska = SymmetricKeyAlgorithmTag.Twofish;
                                        break; 

                                    case "CAMELLIA128":
                                        _ska = SymmetricKeyAlgorithmTag.Camellia128;
                                        break;

                                    case "CAMELLIA192":
                                        _ska = SymmetricKeyAlgorithmTag.Camellia192;
                                        break;

                                    case "CAMELLIA256":
                                        _ska = SymmetricKeyAlgorithmTag.Camellia256;
                                        break;

                                    default:
                                        throw new Exception("Invalid Pgp symmetric cipher!");
                                }
                                break;

                            case "-u":
                            case "--crossbreeding":
                                _crossbreeding = true;
                                break;

                            case "-5":
                            case "--rounds":
                                if (!Turn.ToInt32(Program.CheckArg(args, ++i), ref _rounds) || _rounds < 1)
                                    throw new Exception("The rounds can not be less than 1!");

                                break;

                            case "-4":
                            case "--rc5-64b":
                                _rc5b64 = true;
                                break;

                            case "-3":
                            case "--vmpc-ksa3":
                                _ksa3 = true;
                                break;

                            case "-j":
                            case "--tell-apart":
                                _tellapart = true;
                                break;

                            case "-w":
                            case "--overwrite":
                                _overwrite = true;
                                break;

                            case MOD_SHORT_IO_OPTIONS:
                            case MOD_LONG_IO_OPTIONS:
                                
                                ifp = Program.CheckArg(args, ++i).Split
                                (
                                      _io_options_separator
                                    , StringSplitOptions.RemoveEmptyEntries
                                );

                                foreach (string s in ifp) switch (s.Trim().ToLower())
                                { 
                                    case "basic":
                                        _findermode = Finder.Mode.Basic;
                                        break;

                                    case "glob":
                                        _findermode = Finder.Mode.Glob;
                                        break;

                                    case "extglob":
                                        _findermode = Finder.Mode.ExtendedGlob;
                                        break;

                                    case "regex":
                                        _findermode = Finder.Mode.Regex;
                                        break;

                                    case "unignore-case":
                                        _ignorecase = false;
                                        break;

                                    case "recursively":
                                        _recursively = true;
                                        break;

                                    case "reverse":
                                        _reverse = true;
                                        break;

                                    default:
                                        throw new Exception("Invalid input-output option: \"" + s + '"');
                                }

                                Array.Clear(ifp, 0, ifp.Length);
                                break;

                            case MOD_LONG_EXPORT:
                                if (i + 1 <= l - 1)
                                    Program.CheckArg(args, i + 1, false);

                                _export = true;
                                break;

                            case "--encoding":
                                switch (Program.CheckArg(args, ++i).ToUpper())
                                {
                                    case "ASCII":
                                        _encoding = Encoding.ASCII;
                                        break;

                                    case "UNICODE":
                                    case "UNICODE-LE":
                                        _encoding = Encoding.Unicode;
                                        break;

                                    case "UNICODE-BE":
                                        _encoding = Encoding.BigEndianUnicode;
                                        break;

                                    case "UTF-7":
                                        _encoding = Encoding.UTF7;
                                        break;

                                    case "UTF-8":
                                        _encoding = Encoding.UTF8;
                                        break;

                                    case "UTF-32":
                                        _encoding = Encoding.UTF32;
                                        break;

                                    default:
                                        throw new Exception("Invalid encoding mode!");
                                }

                                tenc = _encoding;
                                break;

                            case "--without-iv-tweak":
                                _without_iv = true;
                                break;

                            case "--rsa-bouncy-castle":
                                _rsa_bc = true;
                                break;

                            case "--signature":
                                _sign = Program.CheckArg(args, ++i, false);

                                if (_sign.Equals(PSS, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    _sign     = Program.CheckArg(args, ++i, false);
                                    _rsa_sign = PSS;
                                }

                                else if (_sign.Equals(ISO9796D2, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    _sign     = Program.CheckArg(args, ++i, false);
                                    _rsa_sign = ISO9796D2;
                                }

                                else if (_sign.Equals(RSA, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    _sign     = Program.CheckArg(args, ++i, false);
                                    _rsa_sign = RSA;
                                }

                                break;

                            case "--certainty:":
                                if (!Turn.ToByte(Program.CheckArg(args, ++i), ref _certainty) || _certainty > 100 || _certainty < 1)
                                    throw new Exception("Invalid certainty value. The number must be between 1 and 100!");

                                break;

                            case "--public-exponent:":
                                if (!Turn.ToInt64(Program.CheckArg(args, ++i), ref _public_exponent) || !BigInteger.ValueOf(_public_exponent).IsProbablePrime(100))
                                    throw new Exception("Invalid public exponent value. The number must be prime!");

                                break;


                            case "--small-primes:":
                                if (!Turn.ToInt32(Program.CheckArg(args, ++i), ref _small_primes) || _small_primes < 30)
                                    throw new Exception("Invalid small primes value. The number can not be less than 30!");

                                break;

                            case "--gost-box":
                                _sbox = Program.CheckArg(args, ++i, true, 0).ToUpper();
                                break;

                            case "--pgp-algorithm":
                                _pgp_algorithm = Program.CheckArg(args, ++i).ToUpper();
                                break;

                            case "--pgp-id":
                                _pgp_id = Program.CheckArg(args, ++i).ToUpper();
                                break;

                            case "--pgp-sha1":
                                _sha1 = true;
                                break;

                            case "--pgp-master":
                                _pgp_master = Program.CheckArg(args, ++i).ToUpper();
                                break;

                            case "--pgp-signature":
                                _pgp_sign = true;
                                break;

                            case "--pgp-compress":
                                switch (Program.CheckArg(args, ++i).ToUpper())
                                {
                                    case "BZIP2":
                                        _cat = CompressionAlgorithmTag.BZip2;
                                        break;

                                    case "ZIP":
                                        _cat = CompressionAlgorithmTag.Zip;
                                        break;

                                    case "ZLIB":
                                        _cat = CompressionAlgorithmTag.ZLib;
                                        break;

                                    case "NONE":
                                        _cat = CompressionAlgorithmTag.Uncompressed;
                                        break;

                                    default:
                                        throw new Exception("Invalid Pgp compression algorithm!");
                                }
                                break;

                            case "--ies-cipher":
                                _ies_cipher = Program.CheckArg(args, ++i, true, 0).ToUpper();
                                break;

                            case "--curve":
                                saux = Program.CheckArg(args, ++i).ToLower();

                                if (_curve.Count > 1)
                                    _curve.RemoveAt(0);

                                _curve.Add
                                (
                                    AbstractCurve.Create
                                    (
                                          saux
                                        , string.IsNullOrEmpty(_curvestore) ? 
                                          Program.GetCurveStoreName(saux)   : 
                                          _curvestore
                                    )
                                );
                                break;

                            case CURVE_STORE:
                                _curvestore = Program.CheckArg(args, ++i).ToUpper();
                                break;

                            case "--show-store-curves":
                                if (++i <= l - 1)
                                    if (String.Compare(_curvestore = Program.CheckArg(args, i, false).ToUpper(), CURVE_STORE, true) == 0)
                                        --i;

                                caux = true;
                                break;

                            case "--raise-pwd-exception":
                                _raisepwd = true;
                                break;

                            case "--inhibit-errors":
                                _raise = false;
                                break;

                            case "--inhibit-esc-chars":
                                _unesc = true;
                                break;

                            case "--inhibit-delimiter":
                                _pathdelimiter = false;
                                break;

                            case MOD_LONG_HELP:
                                if (++i <= l - 1)
                                    Program.ShowHelp(Program.CheckArg(args, i, false));

                                else
                                {
                                    Program.ShowHelp();
                                    Environment.Exit(0);
                                }

                                break;

                            case "--examples":
                                if (++i <= l - 1)
                                {
                                    saux = Program.CheckArg(args, i, false).ToLower();

                                    if (saux == MOD_SHORT_MODE || saux == MOD_LONG_MODE)
                                        --i;

                                    else
                                    {
                                        Program.ShowExamples(saux);
                                        Environment.Exit(0);
                                    }
                                }

                                baux = true;
                                break;

                            case "--input-notes":
                                Program.ShowInputNotes();
                                Environment.Exit(0);
                                break;

                            default:
                                ifn = Program.CheckArg(args, i, false);

                                if (ifn.Equals(BATCH, StringComparison.InvariantCultureIgnoreCase))
                                    ifn += Program.CheckArg(args, ++i, false);

                                break;
                        }
                    }

                    if (_job == CryptoJob.OTHER && _mode != DIGEST && _mode != CHECKSUM && !string.IsNullOrEmpty(ifn))
                        throw new Exception(MSG_MALFORMED_CMD_LINE);

                    if (baux)
                    {
                        if (!string.IsNullOrEmpty(_mode))
                            Program.ShowExamples(_mode);

                        else
                        {
                            string[] modes =
                            { 
                                  B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15
                                , B16, B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27
                                , B28, B29, B30, B31, B32, B33, B34, B35, B36, B37, B38, B39
                                , B40, B41, B42, B43, B44, B45, B46, B47, B48, B49, B50, B51
                                , B52, B53, B54, B55, B56, B57, B58, B59, B60, B61, B62, B63
                                , B64, DIGEST, CHECKSUM, AES, RIJNDAEL, TDES, DES, MARS
                                , SALSA20, XSALSA20, CHACHA, VMPC, RC2, CAMELLIA, BLOWFISH
                                , TWOFISH, THREEFISH, SERPENT, CAST5, CAST6, IDEA, NOEKEON
                                , TEA, XTEA, GOST, SEED, SKIPJACK, RC4, RC5, RC6, HC, ISAAC
                                , ECIES, DLIES, RSA, PGP, ELGAMAL, NACCACHE, ECDH
                            };

                            foreach (string s in modes)
                                Program.ShowExamples(s);
                        }

                        Environment.Exit(0);
                    }

                    if (caux)
                    {
                        Program.DisplayCurveNames();
                        Environment.Exit(0);
                    }

                    if (_export && _generator)
                        throw new Exception(MSG_EXPORT_USE);

                    if (_random && _job != CryptoJob.ENCRYPT)
                    {
                        _random = false;
                        Messenger.Print
                        (
                              Messenger.Icon.WARNING
                            , string.Format(MSG_GENERIC_USE, RNDGEN)
                            , false
                            , true
                        );
                    }

                    Program.ShowBanner();

                    if (_job == CryptoJob.OTHER)
                    {
                        if (_mode == DIGEST || _mode == CHECKSUM)
                        {
                            if (!File.Exists(ifn))
                                throw new Exception("Invalid input file name!");

                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1110111111111111, 0x1111111111111111, 0x1111101);

                            using (FileStream fsr = File.OpenRead(ifn))
                            {
                                _key = _mode == DIGEST ? Program.ComputeHashFromStream(Program.GetHashAlgorithm(), fsr) : Program.Checksum(fsr);

                                if (string.IsNullOrEmpty(ofn))
                                {
                                    if (_key.Length > System.Console.BufferWidth - 5)
                                        _key += '\n';

                                    Messenger.Print(Messenger.Icon.INFORMATION, _key);
                                    Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                                }

                                else
                                {
                                    if (!Program.ValidatePath(ofn) || Path.GetFullPath(ifn) == Path.GetFullPath(ofn))
                                        throw new Exception(MSG_INVALID_OUTPUT);

                                    if (Program.OverwriteFileCheck(ofn, _overwrite))
                                    {
                                        key = Encoding.ASCII.GetBytes(_key);

                                        using (FileStream fsw = File.Create(ofn))
                                            fsw.Write(key, 0, key.Length);

                                        Array.Clear(key, 0, key.Length);
                                        Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                                    }
                                }
                            }

                            Environment.Exit(0);
                        }

                        else if (_generator && _mode == RSA)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111111111110111, 0x0111111110100111, 0x1001100);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            Program.RsaValidateKeySize();

                            if (_rsa_bc)
                                Program.RsaKeyPairGen();

                            else using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(_keysize))
                                Program.RsaKeyPairGen(rsa);

                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_export && _mode == RSA)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111101111110111, 0x1111110110000111, 0x1110000);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            if (_cer.Count > 0)
                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, false))
                                    Program.RsaKeyPairGen(rsa);

                            else if (!string.IsNullOrEmpty(_export_pvk))
                            {
                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                {
                                    baux = Program.RsaImportKey(rsa, _private_key, false);
                                    
                                    _private_key = _export_pvk;
                                    if (!string.IsNullOrEmpty(_export_pbk))
                                        _public_key = _export_pbk;

                                    if (!_rsa_bc)
                                        Program.PgpRsaKeyPairGen(_format == CryptoFormat.ARMORED, rsa);

                                    else
                                    {
                                        if (baux) _rsa_bc = false;
                                        Program.RsaKeyPairGen(rsa);
                                    }
                                }
                            }

                            else if (!string.IsNullOrEmpty(_export_pbk))
                            {
                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                {
                                    baux = Program.RsaImportKey(rsa, _public_key, true);

									_public_key = _export_pbk;
                                    if (!string.IsNullOrEmpty(_export_pvk))
                                        _private_key = _export_pvk;

                                    if (!_rsa_bc)
                                        Program.PgpRsaKeyPairGen(_format == CryptoFormat.ARMORED, rsa);

                                    else
                                    {
                                        if (baux) _rsa_bc = false;
                                        Program.RsaKeyPairGen(rsa);
                                    }
                                }
                            }

                            else throw new Exception(MSG_INVALID_EXPORT_PARAMS);

                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_generator && _mode == PGP)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111111111111111, 0x0101110110100111, 0x1000000);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            if (_pgp_sign) 
                                Messenger.Print(Messenger.Icon.WARNING, MSG_PGP_SIGN_USE, false, true);

                            if (_pgp_algorithm == RSA) 
                                Program.PgpRsaKeyPairGen(_format == CryptoFormat.ARMORED);

                            else if (_pgp_algorithm == ELGAMAL)
                            {
                                if (_keysize == -1)
                                    _keysize = 768;

                                Program.PgpElGamalKeyPairGen(_format == CryptoFormat.ARMORED);
                            }

                            else if (_pgp_algorithm == ECDH)
                                Program.PgpEcdhKeyPairGen(_format == CryptoFormat.ARMORED);

                            else throw new Exception(MSG_INVALID_PGP_ALGORITHM);

                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_export && _mode == PGP)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111101111111111, 0x1111110110000111, 0x1110000);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            if (_pgp_sign) 
                                Messenger.Print(Messenger.Icon.WARNING, MSG_PGP_SIGN_USE, false, true);

                            if (_cer.Count > 0)
                            {
                                if (_pgp_algorithm != RSA) Messenger.Print
                                (
                                      Messenger.Icon.WARNING
                                    , MSG_CER_ALG_INCOMPATIBLE
                                    , false
                                    , true
                                );

                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, false))
                                {
                                    if (!string.IsNullOrEmpty(_export_pwd))
                                        _password = _export_pwd;

                                    else if (!string.IsNullOrEmpty(_password) && !Program.Question(MSG_EXPORT_PWD_QUESTION))
                                        _password = string.Empty;

                                    Program.PgpRsaKeyPairGen(_format == CryptoFormat.ARMORED, rsa);
                                }
                            }

                            else
                            {
                                if (!string.IsNullOrEmpty(_private_key))
                                {
                                    if (string.IsNullOrEmpty(_export_pvk) || !File.Exists(_private_key))
                                        throw new Exception(MSG_INVALID_PRIVATE_KEY);

                                    _pgp_pvk = Program.GetPgpPrivateKey();
                                }

                                if (!string.IsNullOrEmpty(_public_key))
                                {
                                    if (string.IsNullOrEmpty(_export_pbk))
                                        _export_pbk = _public_key;

                                    else
                                    {
                                        if (!File.Exists(_public_key))
                                            throw new Exception(MSG_INVALID_PUBLIC_KEY);

                                        _pgp_pbk = Program.GetPgpPublicKey();
                                    }
                                }

                                if (_pgp_pvk != null)
                                {
                                    if ((baux = _pgp_pvk != null) && !Program.IsReciprocalPgpKeys(_pgp_pbk, _pgp_pvk))
                                        throw new Exception(MSG_NON_RECIPROCAL_KEYS);

                                    Program.AssertPgpAlgorithm(_pgp_pvk.PublicKeyPacket.Algorithm);
                                }

                                else if (_pgp_pbk != null)
                                {
                                    if (!baux && _pgp_pvk != null && !Program.IsReciprocalPgpKeys(_pgp_pbk, _pgp_pvk))
                                        throw new Exception(MSG_NON_RECIPROCAL_KEYS);

                                    Program.AssertPgpAlgorithm(_pgp_pbk.Algorithm);
                                }

                                else throw new Exception(MSG_INVALID_EXPORT_PARAMS);

                                _private_key = _export_pvk;
                                _public_key  = _export_pbk;

                                switch (_pgp_algorithm)
                                {
                                    case RSA:
                                        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                        {
                                            if (_pgp_pvk != null)
                                                Program.PgpPrivateKeyToRsa(_pgp_pvk, rsa);

                                            else if (_pgp_pbk != null)
                                                Program.PgpPublicKeyToRsa(_pgp_pbk, rsa);

                                            Program.RsaKeyPairGen(rsa);
                                        }

                                        break;

                                    case ELGAMAL:
                                        Program.ElGamalKeyPairGen
                                        (
                                              true
                                            , Program.PgpPublicKeyToElGamal(_pgp_pbk)
                                            , Program.PgpPrivateKeyToElGamal(_pgp_pvk)
                                        );

                                        break;

                                    case ECDH:
                                        Program.EcdhKeyPairGen
                                        (
                                            new AsymmetricCipherKeyPair
                                            (
                                                  Program.PgpPublicKeyToEcdh(_pgp_pbk)
                                                , Program.PgpPrivateKeyToEcdh(_pgp_pvk)
                                            )
                                        );

                                        break;
                                }
                            }

                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_generator && _mode == ELGAMAL)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111111111111111, 0x1111111110100111, 0x1001100);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            Program.ValidateKeySize(384, 16384, 768);
                            Program.ElGamalKeyPairGen();
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_export && _mode == ELGAMAL)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111111111111111, 0x1111110110100111, 0x1110000);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            apvk = Program.ImportAsymmetricKey
                            (
                                  _private_key
                                , false
                                , MSG_INVALID_PRIVATE_KEY
                            );

                            apbk = Program.ImportAsymmetricKey
                            (
                                  _public_key
                                , true
                                , MSG_INVALID_PUBLIC_KEY
                            );
                            _private_key = _export_pvk;
                            _public_key  = _export_pbk;

                            Program.PgpElGamalKeyPairGen
                            (
                                  _format == CryptoFormat.ARMORED
                                , new AsymmetricCipherKeyPair(apbk, apvk)
                            );

                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_generator && _mode == NACCACHE)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111111111111111, 0x1111111110100111, 0x1001100);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            if (_keysize == -1)
                                _keysize = 768;
                            
                            Program.NaccacheSternKeyPairGen();
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_generator && _mode == ECIES || _mode == DLIES)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);

                            if (_mode == DLIES)
                            {
                                Program.ValidateParams(0, 0x10000000000000);
                                //Program.ValidateKeySize(768, 768, 768);
                            }

                            Program.ValidateParams(0x1111111111111111, 0x1101111110100111, 0x1100);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            Program.IesKeyPairGen();
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_generator && _mode == ECDH)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111111111111111, 0x1111111110100111, 0x1001100);
                            Program.EcdhKeyPairGen(true);
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else if (_export && _mode == ECDH)
                        {
                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);
                            Program.ValidateParams(0x1111111111111111, 0x1111110110100111, 0x1110000);

                            if (!string.IsNullOrEmpty(ofn)) Messenger.Print
                            (
                                  Messenger.Icon.WARNING
                                , string.Format(MSG_GENERIC_USE, OUT)
                                , false
                                , true
                            );

                            apvk = Program.ImportAsymmetricKey
                            (
                                  _private_key
                                , false
                                , MSG_INVALID_PRIVATE_KEY
                            );

                            apbk = Program.ImportAsymmetricKey
                            (
                                  _public_key
                                , true
                                , MSG_INVALID_PUBLIC_KEY
                            );
                            _private_key = _export_pvk;
                            _public_key = _export_pbk;

                            Program.PgpEcdhKeyPairGen
                            (
                                  _format == CryptoFormat.ARMORED
                                , new AsymmetricCipherKeyPair(apbk, apvk)
                            );

                            Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                            Environment.Exit(0);
                        }

                        else throw new Exception("Invalid encrypt-encode or decrypt-decode operation indicator!");
                    }

                    if (_generator && _job == CryptoJob.DECRYPT)
                        throw new Exception(MSG_GEN_WITH_CER_DECRYPT);

                    if (_export)
                    {
                        Messenger.Print(Messenger.Icon.WARNING, MSG_EXPORT_USE, false, true);
                        _export = false;
                    }

                    saux = "It's not possible to process key files and certificates at the " +
                           "same time.\n\n> Do you want to discard the certificates?";

                    if (_cer.Count > 0)
                    {
                        if (!string.IsNullOrEmpty(_private_key) || !string.IsNullOrEmpty(_public_key))
                        {
                            if (Program.Question(saux))
                                _cer.Clear();

                            else
                            {
                                _public_key  = string.Empty;
                                _private_key = string.Empty;
                            }
                        }
                    }

                    if (ofn.EndsWith(Path.DirectorySeparatorChar.ToString()))
                        ofn = ofn.Remove(ofn.Length - 1);

                    if (baux = ifn.IndexOf(BATCH, StringComparison.InvariantCultureIgnoreCase) == 0)
                        ifn = ifn.Substring(5);

                    ofp = !_pathdelimiter ? new string[] { ifn } : ifn.Split
                    (
                          _path_delimiter
                        , StringSplitOptions.RemoveEmptyEntries
                    );

                    _finder = new Finder(_findermode);
                    _finder.RaiseAccessDenied = false;

                    foreach (string s in ofp) list.AddRange
                    (
                        _finder.GetFiles
                        (
                              s
                            , _ignorecase
                            , _reverse
                            , _recursively
                        )
                    );

                    Array.Clear(ofp, 0, ofp.Length);
                    ifp = list.ToArray();
                    list.Clear();

                    if (baux)
                    {
                        foreach (string s in ifp)
                        {
                            using (FileStream fsr = File.OpenRead(s))
                            {
                                using (StreamReader sr = new StreamReader(fsr))
                                {
                                    while (sr.Peek() >= 0)
                                    {
                                        if (!_pathdelimiter)
                                             ofp = new string[] { sr.ReadLine() };

                                        else ofp = sr.ReadLine().Split
                                        (
                                              _path_delimiter
                                            , StringSplitOptions.RemoveEmptyEntries
                                        );
                                        
                                        l = ofp.Length;
                                        for (int i = 0; i < l; ++i) list.AddRange
                                        (
                                            _finder.GetFiles
                                            (
                                                  ofp[i]
                                                , _ignorecase
                                                , _reverse
                                                , _recursively
                                            )
                                        );

                                        Array.Clear(ofp, 0, l);
                                    }
                                }
                            }
                        }

                        Array.Clear(ifp, 0, ifp.Length);
                        ifp = list.ToArray();
                        list.Clear();
                    }

                    if ((l = ifp.Length) < 1) 
                        throw new Exception(String.Format(MSG_FILE_WAS_NOT_FOUND, ifn));

                    else if (l == 1)
                    {
                        _tellapart = false;
                        _raise     = true;

                        if (string.IsNullOrEmpty(ofn))
                            ofn = ifp[0];

                        else
                        {   
                            ofp = _finder.GetDirectories(ofn, _ignorecase);

                            if (ofp.Length == 1)
                                ofn = ofp[0] + Path.DirectorySeparatorChar + Path.GetFileName(ifp[0]);

                            else if (ofp.Length > 1)
                                throw new Exception(MSG_INVALID_OUTPUT);

                            else
                            {
                                Array.Clear(ofp, 0, ofp.Length);

                                ofp = _finder.GetFiles(ofn, _ignorecase);

                                if (ofp.Length == 1)
                                    ofn = ofp[0];

                                else if (ofp.Length > 1)
                                    throw new Exception(MSG_INVALID_OUTPUT);
                            }

                            Array.Clear(ofp, 0, ofp.Length);
                        }

                        if (!Program.ValidatePath(ofn))
                            throw new Exception(MSG_INVALID_OUTPUT);

                        Program.OverwriteFileCheck(ofn = Path.GetFullPath(ofn), _overwrite);
                    }

                    else if (l > 1)
                    {
                        if (string.IsNullOrEmpty(ofn))
                            iaux = l;

                        else
                        {
                            ofp  = _finder.GetDirectories(ofn, _ignorecase);
                            ofn  = string.Empty;
                            iaux = 0;

                            if (ofp.Length == 1)
                            {
                                path = Path.GetFullPath(ofp[0]) + Path.DirectorySeparatorChar;

                                foreach (string s in ifp)
                                    if (File.Exists(path + Path.GetFileName(s)))
                                        ++iaux;

                                if (iaux < 1)
                                    _overwrite = true;
                            }

                            else if (ofp.Length > 1)
                                throw new Exception(MSG_INVALID_OUTPUT);

                            else
                            {
                                ofn  = "The specified output file will not be considered.";
                                iaux = l;
                            }

                            Array.Clear(ofp, 0, ofp.Length);
                        }

                        if (!_overwrite) Program.Question
                        (
                              l + " files were found, of which " + iaux + " will be overwritten. " + ofn + 
                              MSG_CONTINUE_QUESTION
                            , true
                        );
                    }

                    Messenger.Print(Messenger.Icon.INFORMATION, MSG_PROCESSING);

                    baux = caux = false;
                    if (_mode != RSA && _mode != ELGAMAL)
                        daux = false;

	                for (int i = 0; i < l; ++i)
	                {
                        try
					    {
	                        ifn        = Path.GetFullPath(ifp[i]);
                            _overwrite = false;
	
	                        if (!string.IsNullOrEmpty(path))
	                            ofn = path + Path.GetFileName(ifn);

                            else if ((_overwrite = l > 1))
	                            ofn = Path.GetTempFileName();
	
	                        if (ifn == ofn)
	                        {
	                            ofn        = Path.GetTempFileName();
                                _overwrite = true;
	                        }

		                    using (FileStream fsr = File.OpenRead(ifn))
		                    {
		                        using (FileStream fsw = File.Create(ofn))
		                        {
		                            switch (_mode)
		                            {
	                                    case BIN:
	                                        _mode = B2;
	                                        goto case B63;
	
	                                    case HEX:
	                                        _mode = B16;
	                                        goto case B63;
	
	                                    case OCTAL:
	                                        _mode = B8;
	                                        goto case B63;
	
	                                    case DECIMAL:
	                                        _mode = B10;
	                                        goto case B63;
	
	                                    case B2:
	                                    case B3:
	                                    case B4:
	                                    case B5:
	                                    case B6:
	                                    case B7:
	                                    case B8:
	                                    case B9:
	                                    case B10:
	                                    case B11:
	                                    case B12:
	                                    case B13:
	                                    case B14:
	                                    case B15:
	                                    case B16:
	                                    case B17:
	                                    case B18:
	                                    case B19:
	                                    case B20:
	                                    case B21:
	                                    case B22:
	                                    case B23:
	                                    case B24:
	                                    case B25:
	                                    case B26:
	                                    case B27:
	                                    case B28:
	                                    case B29:
	                                    case B30:
	                                    case B31:
	                                    case B33:
	                                    case B34:
	                                    case B35:
	                                    case B36:
	                                    case B37:
	                                    case B38:
	                                    case B39:
	                                    case B40:
	                                    case B41:
	                                    case B42:
	                                    case B43:
	                                    case B44:
	                                    case B45:
	                                    case B46:
	                                    case B47:
	                                    case B48:
	                                    case B49:
	                                    case B50:
	                                    case B51:
	                                    case B52:
	                                    case B53:
	                                    case B54:
	                                    case B55:
	                                    case B56:
	                                    case B57:
	                                    case B58:
	                                    case B59:
	                                    case B60:
	                                    case B61:
	                                    case B62:
	                                    case B63:
                                            Program.ValidateParams(0x1111111111110010, 0x1111111111111111, 0x1111101);

                                            if (!baux)
                                                Program.ValidateParams(1, 0);

	                                        if (_job == CryptoJob.ENCRYPT)
	                                            Program.Encode(fsr, fsw, byte.Parse(_mode.Substring(1)));
	
	                                        else if (_job == CryptoJob.DECRYPT)
	                                            Program.Decode(fsr, fsw, byte.Parse(_mode.Substring(1)));
	
	                                        break;
	
	                                    case B32:
                                            baux = true;

	                                        if (!_rfc4648)
	                                            goto case B63;

                                            Program.ValidateParams(0x1111111111110100, 0x1111111111111111, 0x1111101);
	
	                                        if (_job == CryptoJob.ENCRYPT)
	                                            Program.Base32Encode(fsr, fsw);
	
	                                        else if (_job == CryptoJob.DECRYPT)
	                                            Program.Base32Decode(fsr, fsw);
	
	                                        break;
	
	                                    case B64:
                                            baux = true;

	                                        if (!_rfc4648)
	                                            goto case B63;

                                            Program.ValidateParams(0x1111111111110110, 0x1111111111111111, 0x1111101);
	
	                                        if (_job == CryptoJob.ENCRYPT)
	                                            Program.Base64Encode(fsr, fsw);
	
	                                        else if (_job == CryptoJob.DECRYPT)
	                                            Program.Base64Decode(fsr, fsw);
	
	                                        break;
	
	                                    case RC2:
                                            Program.ValidateParams(0x0000000001111111, 0x0011111111000100, 0x1111110);
                                            Program.ValidateKeySize(40, 128, 128);
                                            Program.ValidateBlockSize((short)(_without_iv ? 0 : 64));

                                            if (!_without_iv)
                                                Program.ValidateIntrinsicPadding();

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoRc2(fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoRc2(fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                    Program.CryptoRc2(fsr, fsw, Program.GetKeyExchangeProvider(rsa, saux, baux));
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoRc2(fsr, fsw);
                                            }

	                                        Program.ClearSymmetricKey();
	                                        break;
	
	                                    case DES:
                                            Program.ValidateParams(0x0000000001111111, 0x0011111111000100, 0x1111110);
                                            Program.ValidateSizes(64, (short)(_without_iv ? 0 : 64));

                                            if (!_without_iv)
                                                Program.ValidateIntrinsicPadding();

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoDes(fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoDes(fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                    Program.CryptoDes(fsr, fsw, Program.GetKeyExchangeProvider(rsa, saux, baux));
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoDes(fsr, fsw);
                                            }

	                                        Program.ClearSymmetricKey();
	                                        break;
	
	                                    case TDES:
                                            Program.ValidateParams(0x0000000001111111, 0x0011111111000100, 0x1111110);

                                            if (_keysize == -1)
                                                _keysize = 192;

                                            else if (_keysize != 128 && _keysize != 192)
                                                throw new Exception(MSG_INVALID_KEY_SIZE);

                                            Program.ValidateBlockSize((short)(_without_iv ? 0 : 64));

                                            if (!_without_iv)
                                                Program.ValidateIntrinsicPadding();

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoTripleDes(fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoTripleDes(fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                    Program.CryptoTripleDes(fsr, fsw, Program.GetKeyExchangeProvider(rsa, saux, baux));
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoTripleDes(fsr, fsw);
                                            }

	                                        Program.ClearSymmetricKey();
	                                        break;
	
	                                    case RIJNDAEL:
                                            Program.ValidateParams(0x0000000001111111, 0x0011111111000000, 0x1111110);

                                            if (_keysize == -1)
                                                _keysize = 256;

                                            else Program.ValidateSizeFrom128To256(_keysize);

                                            if (_blocksize == -1)
                                                _blocksize = 256;

                                            else switch (_blocksize)
                                            {
                                                case 128:
                                                case 160:
                                                case 192:
                                                case 224:
                                                case 256:
                                                    break;

                                                default:
                                                    throw new Exception(MSG_INVALID_BLOCK_SIZE);
                                            }

                                            naux = _blocksize;

                                            if (_without_iv)
                                            {
                                                Program.ValidateParams(0, 0x100);
                                                _blocksize = 0;
                                            }

                                            else
                                            {
                                                Program.ValidateIntrinsicPadding();

                                                if (_feedbacksize == -1)
                                                    _feedbacksize = 128;

                                                else if (_feedbacksize > _blocksize || _feedbacksize % 8 != 0)
                                                    throw new Exception(MSG_INVALID_FEEDBACK_SIZE);
                                            }

                                            if (_cer.Count > 0)
                                            {
                                                _blocksize = naux;
                                                Program.ValidateParams(0x1110000000000, 0);

                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoRijndael(fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                _blocksize = naux;
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoRijndael(fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                _blocksize = naux;
                                                Program.ValidateParams(0x1110000000000, 0);

                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                    Program.CryptoRijndael(fsr, fsw, Program.GetKeyExchangeProvider(rsa, saux, baux));
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);

                                                _blocksize = naux;
                                                Program.CryptoRijndael(fsr, fsw);
                                            }

	                                        Program.ClearSymmetricKey();
	                                        break;
	
	                                    case AES:
                                            Program.ValidateParams(0x0000000001111111, 0x0011111111000000, 0x1111110);
                                            Program.ValidateBlockSize((short)(_without_iv ? 0 : 128));
                                            Program.ValidateFeedbackSize(128);

                                            if (_keysize == -1)
                                                _keysize = 256;

                                            else Program.ValidateSizeFrom128To256(_keysize);

                                            if (!_without_iv)
                                            {
                                                Program.ValidateIntrinsicPadding();

                                                if (_ciphermode == CipherMode.OFB || _ciphermode == CipherMode.CFB)
                                                    throw new Exception(MSG_INVALID_CIPHER_MODE);
                                            }

                                            else if (_ciphermode != CipherMode.CBC)
                                                throw new Exception(MSG_INVALID_CIPHER_MODE);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoAes(fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoAes(fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                    Program.CryptoAes(fsr, fsw, Program.GetKeyExchangeProvider(rsa, saux, baux));
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoAes(fsr, fsw);
                                            }

	                                        Program.ClearSymmetricKey();
		                                    break;
	
	                                    case MARS:
                                            Program.ValidateParams(0x0000000001111111, 0x0111111111000100, 0x1111110);

                                            if (_padding != CryptoPadding.PKCS7)
                                                throw new Exception(MSG_INVALID_PADDING_MODE);

                                            Program.ValidateKeySize(128, 448, 256);
                                            Program.ValidateBlockSize(128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoMars(fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoMars(fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                    Program.CryptoMars(fsr, fsw, Program.GetKeyExchangeProvider(rsa, saux, baux));
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoMars(fsr, fsw);
                                            }

	                                        Program.ClearSymmetricKey();
                                            break;

                                        case THREEFISH:
                                            Program.ValidateParams(0x0000000001111111, 0x0011111111000100, 0x1111110);

                                            if (_keysize == -1)
                                                _keysize = 256;

                                            else Program.ValidateSizeFrom256to1024(_keysize);

                                            Program.ValidateBlockSize((short)(_without_iv ? 0 : 128));

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoThreefish(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoThreefish(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoThreefish
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoThreefish(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
                                            break;

                                        case HC:
                                            Program.ValidateParams(0x0000000001111111, 0x0111111111000100, 0x1111110);

                                            if (_blocksize == -1)
                                                _blocksize = 128;

                                            if (_keysize == -1)
                                                _keysize = 256;

                                            else switch (_keysize)
                                            {
                                                case 128:
                                                    if (_blocksize != 128)
                                                        throw new Exception(MSG_INVALID_BLOCK_SIZE);

                                                    break;

                                                case 256:
                                                    if (_blocksize != 128 && _blocksize != 256)
                                                        throw new Exception(MSG_INVALID_BLOCK_SIZE);

                                                    break;

                                                default:
                                                    throw new Exception(MSG_INVALID_KEY_SIZE);
                                            }

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoHongjun(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoHongjun(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoHongjun
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoHongjun(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
                                            break;

                                        case XSALSA20:
                                            Program.ValidateParams(0x10000, 0, 0);
                                            baux = true;
                                            goto case SALSA20;

                                        case CHACHA:
                                            caux = true;
                                            goto case SALSA20;

                                        case SALSA20:
                                            Program.ValidateParams(0x0000000001101111, 0x0111111111000100, 0x1111110);

                                            if (_keysize == -1)
                                                _keysize = 256;

                                            else switch (_keysize)
                                            {
                                                case 128:
                                                    if (baux)
                                                        goto default;

                                                    break;

                                                case 256:
                                                    break;

                                                default:
                                                    throw new Exception(MSG_INVALID_KEY_SIZE);
                                            }

                                            Program.ValidateBlockSize((short)(baux ? 192 : 64));

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                {
                                                    if (baux) Program.CryptoXSalsa20
                                                    (
                                                          _job == CryptoJob.ENCRYPT
                                                        , fsr
                                                        , fsw
                                                        , rsa
                                                    );

                                                    else if (caux) Program.CryptoChaCha
                                                    (
                                                          _job == CryptoJob.ENCRYPT
                                                        , fsr
                                                        , fsw
                                                        , rsa
                                                    );

                                                    else Program.CryptoSalsa20
                                                    (
                                                          _job == CryptoJob.ENCRYPT
                                                        , fsr
                                                        , fsw
                                                        , rsa
                                                    );
                                                }
                                            }

                                            else if (Program.ResolveEcdhKeyExchange(true))
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                if (baux) Program.CryptoXSalsa20
                                                    (
                                                          _job == CryptoJob.ENCRYPT
                                                        , fsr
                                                        , fsw
                                                    );

                                                else if (caux) Program.CryptoChaCha
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                );

                                                else Program.CryptoSalsa20
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                );
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                {
                                                    Program.RsaImportKey(rsa, saux, baux);

                                                    if (baux) Program.CryptoXSalsa20
                                                    (
                                                          _job == CryptoJob.ENCRYPT
                                                        , fsr
                                                        , fsw
                                                        , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                    );

                                                    else if (caux) Program.CryptoChaCha
                                                    (
                                                          _job == CryptoJob.ENCRYPT
                                                        , fsr
                                                        , fsw
                                                        , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                    );

                                                    else Program.CryptoSalsa20
                                                    (
                                                          _job == CryptoJob.ENCRYPT
                                                        , fsr
                                                        , fsw
                                                        , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                    );
                                                }
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l, true);

                                                if (baux) Program.CryptoXSalsa20
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                );

                                                else if (caux) Program.CryptoChaCha
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                );

                                                else Program.CryptoSalsa20
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                );
                                            }

                                            Program.ClearSymmetricKey();
                                            break;
	
	                                    case VMPC:
                                            Program.ValidateParams(0x0000000000111111, 0x0111111111000100, 0x1111110);
                                            Program.ValidateKeySize(8, 6144, 256);
                                            Program.ValidateBlockSize(8, 6144, 256);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoVmpc(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange(true))
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoVmpc(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoVmpc
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l, true);
                                                Program.CryptoVmpc(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

	                                        Program.ClearSymmetricKey();
	                                        break;

                                        case ISAAC:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(32, 8192, 256);

                                            if (_keysize % 16 != 0)
                                                throw new Exception(MSG_INVALID_KEY_SIZE);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoIsaac(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoIsaac(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoIsaac
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoIsaac(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }
                                            
                                            Program.ClearSymmetricKey();
                                            break;

                                        case RC4:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(40, 2048, 256);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoRc4(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoRc4(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoRc4
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoRc4(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
                                            break;
	
	                                    case CAMELLIA:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);

	                                        if (_keysize == -1)
	                                            _keysize = 256;

                                            else Program.ValidateSizeFrom128To256(_keysize);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoCamellia(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoCamellia(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoCamellia
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoCamellia(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;

                                        case SERPENT:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);

                                            if (_keysize == -1)
                                                _keysize = 256;

                                            else Program.ValidateSizeFrom128To256(_keysize);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoSerpent(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoSerpent(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoSerpent
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoSerpent(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
                                            break;

                                        case TNEPRES:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);

                                            if (_keysize == -1)
                                                _keysize = 256;

                                            else Program.ValidateSizeFrom128To256(_keysize);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoTnepres(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoTnepres(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoTnepres
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoTnepres(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
                                            break;
	
	                                    case BLOWFISH:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(8, 448, 256);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoBlowfish(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoBlowfish(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoBlowfish
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoBlowfish(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case TWOFISH:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);

	                                        if (_keysize == -1)
	                                            _keysize = 256;

                                            else Program.ValidateSizeFrom128To256(_keysize);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoTwofish(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoTwofish(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoTwofish
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoTwofish(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }
                                            
                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case CAST5:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(40, 128, 128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoCast5(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoCast5(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoCast5
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoCast5(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case CAST6:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(40, 256, 256);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoCast6(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoCast6(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoCast6
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoCast6(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case IDEA:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoIdea(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoIdea(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoIdea
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoIdea(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case NOEKEON:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoNoekeon(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoNoekeon(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoNoekeon
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoNoekeon(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case GOST:
                                            Program.ValidateParams(0x0000000001111111, 0x0011011111000100, 0x1111110);
                                            Program.ValidateKeySize(256);

                                            if ((_blocksize = (short)(_sbox == IV ? 1024 : 0)) > 0 && _without_iv)
                                            {
                                                saux = "gost-box with iv and without-iv-tweak parameters can't be " +
                                                       "used simultaneously!\n\n>Do you want to use the initial vector?";

                                                if (!Program.Question(saux))
                                                     _without_iv = false;

                                                else _blocksize = 0;
                                            }

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoGost(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoGost(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoGost
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoGost(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case SEED:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoSeed(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoSeed(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoSeed
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoSeed(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case SKIPJACK:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(40, 128, 128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoSkipjack(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoSkipjack(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoSkipjack
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoSkipjack(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case TEA:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoTea(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoTea(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoTea
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoTea(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case XTEA:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoXTea(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoXTea(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoXTea
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoXTea(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case RC5:
                                            Program.ValidateParams(0x0000001001001111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(40, (short)(_rc5b64 ? 256 : 128), 128);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoRc5(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoRc5(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoRc5
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoRc5(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;
	
	                                    case RC6:
                                            Program.ValidateParams(0x0000001001111111, 0x0011111111000110, 0x1111110);
                                            Program.ValidateKeySize(40, 256, 256);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                    Program.CryptoRc6(_job == CryptoJob.ENCRYPT, fsr, fsw, rsa);
                                            }

                                            else if (Program.ResolveEcdhKeyExchange())
                                            {
                                                Program.ValidateParams(0x110000000000, 0);
                                                Program.CryptoRc6(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            else if ((saux = Program.ResolveKeyExchange(ref baux)) != null)
                                            {
                                                Program.ValidateParams(0x1110000000000, 0);
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) Program.CryptoRc6
                                                (
                                                      _job == CryptoJob.ENCRYPT
                                                    , fsr
                                                    , fsw
                                                    , Program.GetKeyExchangeProvider(rsa, saux, baux)
                                                );
                                            }

                                            else
                                            {
                                                Program.ValidateParams(0, 0x1000000000000000);
                                                Program.ProvideKey(_overwrite ? ifn : ofn, l);
                                                Program.CryptoRc6(_job == CryptoJob.ENCRYPT, fsr, fsw);
                                            }

                                            Program.ClearSymmetricKey();
	                                        break;

                                        case DLIES:
                                            Program.ValidateParams(0x0000000011111111, 0x1110111110100100, 0x1110110);
                                            daux = true;
                                            goto case ECIES;

                                        case ECIES:
                                            if (!daux)
                                                Program.ValidateParams(0x0000000011111111, 0x1100111110100100, 0x1111100);

                                            switch (_ies_cipher)
                                            {
                                                case RIJNDAEL:
                                                    baux = true;

                                                    if (_blocksize == -1)
                                                        _blocksize = 256;

                                                    else switch (_blocksize)
                                                    {
                                                        case 128:
                                                        case 160:
                                                        case 192:
                                                        case 224:
                                                        case 256:
                                                            break;

                                                        default:
                                                            throw new Exception(MSG_INVALID_BLOCK_SIZE);
                                                    }

                                                    goto case TWOFISH;

                                                case AES:
                                                    if (_ciphermode != CipherMode.CBC)
                                                        throw new Exception(MSG_INVALID_CIPHER_MODE);

                                                    goto case TWOFISH;

                                                case SERPENT:
                                                case CAMELLIA:
                                                case TNEPRES:
                                                case TWOFISH:
                                                    if (!baux)
                                                        Program.ValidateBlockSize(128);

                                                    if (_keysize == -1)
                                                        _keysize = 256;

                                                    else Program.ValidateSizeFrom128To256(_keysize);
                                                    break;

                                                case GOST:
                                                    Program.ValidateSizes(256, 0);
                                                    break;

                                                case DES:
                                                    Program.ValidateSizes(64, 0);
                                                    break;

                                                case TDES:
                                                    Program.ValidateBlockSize(0);

                                                    if (_keysize == -1)
                                                        _keysize = 192;

                                                    else if (_keysize != 128 && _keysize != 192)
                                                        throw new Exception(MSG_INVALID_KEY_SIZE);

                                                    break;

                                                case RC5:
                                                    if (!_rc5b64)
                                                        goto case SKIPJACK;

                                                    Program.ValidateKeySize(40, 256, 256);
                                                    Program.ValidateBlockSize(0);
                                                    break;

                                                case RC2:
                                                case SKIPJACK:
                                                    Program.ValidateKeySize(40, 128, 128);
                                                    Program.ValidateBlockSize(0);
                                                    break;

                                                case BLOWFISH:
                                                    Program.ValidateKeySize(40, 448, 256);
                                                    Program.ValidateBlockSize(0);
                                                    break;

                                                case CAST5:
                                                    Program.ValidateKeySize(40, 128, 128);
                                                    Program.ValidateBlockSize(0);
                                                    break;

                                                case CAST6:
                                                case RC6:
                                                    Program.ValidateKeySize(40, 256, 256);
                                                    Program.ValidateBlockSize(0);
                                                    break;
                                                
                                                case SEED:
                                                case NOEKEON:
                                                case TEA:
                                                case XTEA:
                                                case IDEA:
                                                    Program.ValidateSizes(128, 0);
                                                    break;

                                                case THREEFISH:
                                                    Program.ValidateBlockSize(0);

	                                                if (_keysize == -1)
	                                                    _keysize = 256;

                                                    else Program.ValidateSizeFrom256to1024(_keysize);

                                                    break;

                                                default:
                                                    if (!string.IsNullOrEmpty(_ies_cipher))
                                                        throw new Exception(MSG_INVALID_IES_CIPHER);

                                                    caux = true;
                                                    break;
                                            }

                                            if (_generator)
                                            {
                                                Program.IesKeyPairGen();
                                                _generator = false;
                                            }

                                            IDigest d   = Program.GetBouncyCastleDigest();
                                            naux        = _blocksize;
                                            _blocksize  = (short)(d.GetDigestSize() * 8);

                                            if (caux)
                                                _keysize = _blocksize;

                                            Program.ProvideKey(_overwrite ? ifn : ofn, l, true);
                                            _blocksize = naux;

                                            Program.CryptoIes(_job == CryptoJob.ENCRYPT, d, fsr, fsw);
                                            Program.ClearSymmetricKey();
                                            break;

	                                    case RSA:
                                            Program.ValidateParams(0x0110101111110111, 0x0111101100000111, 0x1100);

                                            if (_rsa_bc && !daux)
                                                _padding = CryptoPadding.PKCS1;

                                            if (_padding == CryptoPadding.OAEP && !Program.HasRsaOaep())
	                                            throw new Exception("Microsoft CryptoAPI only supports OAEP since Windows XP!");

                                            baux = Program.SignatureExists();

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0x1000, 0x1001000, 0x110001);
                                                Program.CryptoRsa
                                                (
                                                      Program.GetRsaFromCertificates(0, !baux && _job == CryptoJob.ENCRYPT)
                                                    , fsr
                                                    , fsw
                                                    , baux
                                                    , true
                                                );
                                            }

                                            else
                                            {
                                                if (!_generator)
                                                    Program.ValidateParams(0x1000, 0x1001000, 0x110000);

                                                Program.RsaValidateKeySize();
                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(_rsa_bc || !_generator ? 384 : _keysize))
                                                {
                                                    if (_job == CryptoJob.ENCRYPT)
                                                    {
                                                        if (_generator)
                                                        {
                                                            if (_crossbreeding)
                                                            {
                                                                _crossbreeding = false;
                                                                Messenger.Print
                                                                (
                                                                      Messenger.Icon.WARNING
                                                                    , MSG_CROSS_INCOMPATIBLE
                                                                    , false
                                                                    , true
                                                                );
                                                            }

                                                            Program.RsaKeyPairGen(_rsa_bc ? null : rsa);

                                                            if (_rsa_bc)
                                                            {
                                                                if (baux)
                                                                    Program.RsaImportKey(rsa, _private_key, false);

                                                                else Program.RsaImportKey(rsa, _public_key, true);
                                                            }

                                                            _public_exponent = 0;
                                                            _certainty       = 0;
                                                            _charsperline    = 0;
                                                            _keysize         = -1;
                                                            _format          = CryptoFormat.RAW;
                                                            _generator       = false;
                                                        }

                                                        else
                                                        {
                                                            _keysize = -1;

                                                            if (baux)
                                                            {
                                                                if (!_crossbreeding)
                                                                    Program.RsaImportKey(rsa, _private_key, true);

                                                                else Program.PgpPrivateKeyToRsa
                                                                (
                                                                      Program.GetPgpPrivateKey()
                                                                    , rsa
                                                                );
                                                            }
                                                            else
                                                            {
                                                                if (!_crossbreeding)
                                                                    Program.RsaImportKey(rsa, _public_key, true);

                                                                else Program.PgpPublicKeyToRsa
                                                                (
                                                                      Program.GetPgpPublicKey()
                                                                    , rsa
                                                                );
                                                            }
                                                        }
                                                    }

                                                    else if (_job == CryptoJob.DECRYPT)
                                                    {
                                                        _keysize = -1;

                                                        if (!_crossbreeding)
                                                            Program.RsaImportKey(rsa, _private_key, false);

                                                        else Program.PgpPrivateKeyToRsa
                                                        (
                                                              Program.GetPgpPrivateKey()
                                                            , rsa
                                                        );
                                                    }

                                                    Program.CryptoRsa(rsa, fsr, fsw, baux);
                                                }
                                            }
	
		                                    break;
	
	                                    case PGP:
                                            Program.ValidateParams(0x1110101101111111, 0x0101100010000111, 0x1000000);
                                            
                                            if (_job == CryptoJob.DECRYPT)
                                                Program.ValidateParams(0, 0x1000000000000000, 0x110000);

                                            if (_cer.Count > 0)
                                            {
                                                Program.ValidateParams(0, 0x1000, 0x110001);

                                                if (_pgp_algorithm != RSA)
                                                {
                                                    _pgp_algorithm = RSA;
                                                    Messenger.Print
                                                    (
                                                          Messenger.Icon.WARNING
                                                        , MSG_CER_ALG_INCOMPATIBLE
                                                        , false
                                                        , true
                                                    );
                                                }

                                                if (_pgp_sign)
                                                {
                                                    if (_job == CryptoJob.ENCRYPT)
                                                        using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(1, false))
                                                            _pgp_pvk = Program.GetPgpPrivateKeyFromRsa(rsa);    

                                                    else using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(1, true))
                                                            _pgp_pbk = Program.GetPgpPublicKeyFromRsa(rsa);                                                    
                                                }

                                                using (RSACryptoServiceProvider rsa = Program.GetRsaFromCertificates(0, _job == CryptoJob.ENCRYPT))
                                                {
                                                    if (_job == CryptoJob.ENCRYPT)
                                                    {
                                                        _pgp_pbk = Program.GetPgpPublicKeyFromRsa(rsa);

                                                        Program.PgpEncrypt
                                                        (
                                                              fsr
                                                            , fsw
                                                            , Path.GetFileName(fsw.Name)
                                                            , _format == CryptoFormat.ARMORED
                                                            , true
                                                        );
                                                    }

                                                    else
                                                    {
                                                        _pgp_pvk = Program.GetPgpPrivateKeyFromRsa(rsa);
                                                        Program.PgpDecrypt(fsr, fsw);
                                                    }
                                                }
                                            }

	                                        else
	                                        {
	                                            if (_job == CryptoJob.ENCRYPT)
	                                            {
                                                    if (_generator)
	                                                {
                                                        if (_crossbreeding)
                                                        {
                                                            _crossbreeding = false;
                                                            Messenger.Print
                                                            (
                                                                  Messenger.Icon.WARNING
                                                                , MSG_CROSS_INCOMPATIBLE
                                                                , false
                                                                , true
                                                            );
                                                        }

                                                        baux = _format == CryptoFormat.ARMORED;

                                                        switch (_pgp_algorithm)
                                                        {
                                                            case RSA:
                                                                Program.PgpRsaKeyPairGen(baux);
                                                                break;

                                                            case ELGAMAL:
                                                                Program.PgpElGamalKeyPairGen(baux);
                                                                break;

                                                            case ECDH:
                                                                Program.PgpEcdhKeyPairGen(baux);
                                                                break;

                                                            default:
                                                                throw new Exception(MSG_INVALID_PGP_ALGORITHM);
                                                        }

                                                        _pgp_pbk         = Program.GetPgpPublicKey();
                                                        _public_exponent = 0;
                                                        _certainty       = 0;
                                                        _keysize         = -1;
                                                        _generator       = false;

                                                        if (_pgp_sign)
                                                            _pgp_pvk = Program.GetPgpPrivateKey(true);
	                                                }
	
	                                                else
	                                                {
                                                        Program.ValidateParams(0, 0x1000, 0x110000);

                                                        if (!_crossbreeding)
                                                        {
                                                            if (_pgp_sign)
                                                                _pgp_pvk = Program.GetPgpPrivateKey(true);

                                                            _pgp_pbk = Program.GetPgpPublicKey();
                                                        }

                                                        else switch (_pgp_algorithm)
                                                        {
                                                            case RSA:
                                                                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                                {
                                                                    if (!_pgp_sign)
                                                                        Program.RsaImportKey(rsa, _public_key, true);

                                                                    else
                                                                    {
                                                                        if (!string.IsNullOrEmpty(_public_key))
                                                                        {
                                                                            _public_key = string.Empty;
                                                                            Messenger.Print
                                                                            (
                                                                                  Messenger.Icon.WARNING
                                                                                , MSG_CROSS_RSA_PUB_KEY
                                                                                , false
                                                                                , true
                                                                            );
                                                                        }

                                                                        Program.RsaImportKey(rsa, _private_key, false);
                                                                        _pgp_pvk = Program.GetPgpPrivateKeyFromRsa(rsa);
                                                                    }

                                                                    _pgp_pbk = Program.GetPgpPublicKeyFromRsa(rsa);
                                                                }
                                                                break;

                                                            case ELGAMAL:
                                                                if (_pgp_sign)
                                                                    throw new Exception(MSG_INVALID_ALGO_SIGN);

                                                                apbk = Program.ImportAsymmetricKey
                                                                (
                                                                      _public_key
                                                                    , true
                                                                    , MSG_INVALID_PUBLIC_KEY
                                                                );

                                                                _pgp_pbk = Program.GetPgpPublicKeyFromElGamal((ElGamalPublicKeyParameters)apbk);

                                                                break;

                                                            case ECDH:
                                                                if (_pgp_sign)
                                                                    throw new Exception(MSG_INVALID_ALGO_SIGN);

                                                                apbk = Program.ImportAsymmetricKey
                                                                (
                                                                      _public_key
                                                                    , true
                                                                    , MSG_INVALID_PUBLIC_KEY
                                                                );

                                                                _pgp_pbk = Program.GetPgpPublicKeyFromEcdh((ECPublicKeyParameters)apbk);

                                                                break;

                                                            default:
                                                                throw new Exception(MSG_INVALID_PGP_ALGORITHM);
                                                        }
	                                                }

	                                                Program.PgpEncrypt
	                                                (
	                                                      fsr
	                                                    , fsw
	                                                    , Path.GetFileName(fsw.Name)
                                                        , _format == CryptoFormat.ARMORED
	                                                    , true
	                                                );
	                                            }
	
	                                            else
	                                            {
                                                    Program.ValidateParams(0, 0x1000);

                                                    if (!_crossbreeding)
                                                    {
                                                        _pgp_pvk = Program.GetPgpPrivateKey();

                                                        if (_pgp_sign)
                                                            _pgp_pbk = Program.GetPgpPublicKey(true);
                                                    }

                                                    else switch (_pgp_algorithm)
                                                    {
                                                        case RSA:
                                                            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                                                            {
                                                                Program.RsaImportKey(rsa, _private_key, false);
                                                                _pgp_pvk = Program.GetPgpPrivateKeyFromRsa(rsa);

                                                                if (_pgp_sign)
                                                                {
                                                                    _pgp_pbk = Program.GetPgpPublicKeyFromRsa(rsa);

                                                                    if (!string.IsNullOrEmpty(_public_key))
                                                                    {
                                                                        _public_key = string.Empty;
                                                                        Messenger.Print
                                                                        (
                                                                              Messenger.Icon.WARNING
                                                                            , MSG_CROSS_RSA_PUB_KEY
                                                                            , false
                                                                            , true
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                            break;

                                                        case ELGAMAL:
                                                            if (_pgp_sign)
                                                                throw new Exception(MSG_INVALID_ALGO_SIGN);

                                                            apbk = Program.ImportAsymmetricKey
                                                            (
                                                                _public_key
                                                                , true
                                                                , MSG_INVALID_PUBLIC_KEY
                                                            );

                                                            if (!(apbk is ElGamalPublicKeyParameters))
                                                                throw new Exception(MSG_INVALID_PUBLIC_KEY);

                                                            apvk = Program.ImportAsymmetricKey
                                                            (
                                                                _private_key
                                                                , false
                                                                , MSG_INVALID_PRIVATE_KEY
                                                            );

                                                            if (!(apvk is ElGamalPrivateKeyParameters))
                                                                throw new Exception(MSG_INVALID_PRIVATE_KEY);

                                                            _pgp_pvk = Program.GetPgpPrivateKeyFromElGamal
                                                            (
                                                                  (ElGamalPublicKeyParameters)apbk
                                                                , (ElGamalPrivateKeyParameters)apvk
                                                            );

                                                            break;

                                                        case ECDH:
                                                            if (_pgp_sign)
                                                                throw new Exception(MSG_INVALID_ALGO_SIGN);

                                                            apbk = Program.ImportAsymmetricKey
                                                            (
                                                                _public_key
                                                                , true
                                                                , MSG_INVALID_PUBLIC_KEY
                                                            );

                                                            if (!(apbk is ECPublicKeyParameters))
                                                                throw new Exception(MSG_INVALID_PUBLIC_KEY);

                                                            apvk = Program.ImportAsymmetricKey
                                                            (
                                                                _private_key
                                                                , false
                                                                , MSG_INVALID_PRIVATE_KEY
                                                            );

                                                            if (!(apvk is ECPrivateKeyParameters))
                                                                throw new Exception(MSG_INVALID_PRIVATE_KEY);

                                                            _pgp_pvk = Program.GetPgpPrivateKeyFromEcdh
                                                            (
                                                                  (ECPublicKeyParameters)apbk
                                                                , (ECPrivateKeyParameters)apvk
                                                            );

                                                            break;

                                                        default:
                                                            throw new Exception(MSG_INVALID_PGP_ALGORITHM);
                                                    }

                                                    Program.PgpDecrypt(fsr, fsw);
	                                            }
	                                        }
	
	                                        break;
	
	                                    case ELGAMAL:
                                            Program.ValidateParams(0x0110101111110111, 0x1111101110100111, 0x101100);
                                            baux = Program.SignatureExists();

                                            if (!daux)
	                                            _padding = CryptoPadding.PKCS1;
	
	                                        ElGamalKeyParameters ekp = null;
	
	                                        if (_job == CryptoJob.ENCRYPT)
	                                        {
                                                if (_generator)
                                                {
                                                    if (_crossbreeding)
                                                    {
                                                        _crossbreeding = false;
                                                        Messenger.Print
                                                        (
                                                              Messenger.Icon.WARNING
                                                            , MSG_CROSS_INCOMPATIBLE
                                                            , false
                                                            , true
                                                        );
                                                    }

                                                    if (_keysize == -1)
                                                        _keysize = 768;

                                                    Program.ElGamalKeyPairGen();

                                                    _certainty    = 0;
                                                    _charsperline = 0;
                                                    _generator    = false;
                                                    _format       = CryptoFormat.RAW;
                                                    
                                                    _keysize      = -1;
                                                }

                                                else Program.ValidateParams(0x1000, 0x1001000, 0x10000);

                                                if (_crossbreeding)
                                                    ekp = Program.PgpPublicKeyToElGamal(Program.GetPgpPublicKey());

                                                else
                                                {
                                                    apbk = Program.ImportAsymmetricKey
                                                    (
                                                        _public_key
                                                        , true
                                                        , MSG_INVALID_PUBLIC_KEY
                                                    );

                                                    if (!(apbk is ElGamalPublicKeyParameters))
                                                        throw new Exception(MSG_INVALID_PUBLIC_KEY);

                                                    ekp = (ElGamalKeyParameters)apbk;
                                                }
	                                        }
	
	                                        else if (_job == CryptoJob.DECRYPT)
	                                        {
                                                Program.ValidateParams(0x1000, 0x1001000, 0x10000);

                                                if (_crossbreeding)
                                                    ekp = Program.PgpPrivateKeyToElGamal(Program.GetPgpPrivateKey());

                                                else
                                                {
                                                    apvk = Program.ImportAsymmetricKey
                                                    (
                                                        _private_key
                                                        , false
                                                        , MSG_INVALID_PRIVATE_KEY
                                                    );

                                                    if (!(apvk is ElGamalPrivateKeyParameters))
                                                        throw new Exception(MSG_INVALID_PRIVATE_KEY);

                                                    ekp = (ElGamalKeyParameters)apvk;
                                                }
	                                        }

                                            Program.CryptoElGamal(_job == CryptoJob.ENCRYPT, ekp, fsr, fsw, baux);
	                                        break;

                                        case NACCACHE:
                                            Program.ValidateParams(0x1110111111110111, 0x1111111110100111, 0x101100);
                                            baux = Program.SignatureExists();

                                            NaccacheSternKeyParameters nsk = null;

                                            if (_job == CryptoJob.ENCRYPT)
                                            {
                                                if (!_generator)
                                                    Program.ValidateParams(0x1000, 0x1001000, 0x10000);

                                                else
                                                {
                                                    if (_keysize == -1)
                                                        _keysize = 768;

                                                    Program.NaccacheSternKeyPairGen();

                                                    _certainty    = 0;
                                                    _generator    = false;
                                                    _format       = CryptoFormat.RAW;
                                                    _charsperline = 0;
                                                    _keysize      = -1;
                                                }

                                                nsk = Program.NaccacheSternImportKey(_public_key, true);
                                            }

                                            else if (_job == CryptoJob.DECRYPT)
                                            {
                                                Program.ValidateParams(0x1000, 0x1001000, 0x10000);
                                                nsk = Program.NaccacheSternImportKey(_private_key, false);
                                            }

                                            Program.CryptoNaccacheStern
                                            (
                                                  _job == CryptoJob.ENCRYPT
                                                , nsk
                                                , fsr
                                                , fsw
                                                , baux
                                            );

                                            break;
	
		                                default:
		                                    throw new Exception("Invalid mode!");
		                            }
		                        }
							}

                            if (_tellapart)
                                _encoding = tenc;

                            if (_overwrite)
	                            Program.MoveFile(ofn, ifn);

                            else if (l > 1) Messenger.Print
                            (
                                  Messenger.Icon.INFORMATION
                                , string.Format
                                  (
                                        "Process completed with the file \"{0}\" in \"{1}\""
                                      , Path.GetFileName(ofn)
                                      , Path.GetDirectoryName(ofn)
                                  )
                                , false
                                , true
                            );

                            _e_num = 0;
						}

                        catch (Exception e)
                        {
                            if (_percent < 100)
                                Program.Progress(1, 1, 0);

                            if (!_overwrite && File.Exists(ofn))
                                File.Delete(ofn);

                            switch (iaux = Marshal.GetHRForException(e))
                            {
                                case -2146233088:
                                    if (_mode != RSA && _mode != ELGAMAL && e.Message.Contains("pad block corrupted"))
                                        goto case -2146893819;

                                    break;

                                case -2146233296:
                                case -2146893819:
                                    if (_keyexchange)
                                        e = new Exception("Wrong public or private key!", e);

                                    else if (_haspwd)
                                    {
                                        if (_raisepwd)
                                            e = new Exception(MSG_WRONG_PWD_SALT + '!');

                                        else
                                        {
                                            Messenger.Print
                                            (
                                                  Messenger.Icon.ERROR
                                                  , MSG_WRONG_PWD_SALT + 
                                                  (l < 2 ? "! " : " for the file \""  +
                                                  (_overwrite ? ifn : ofn) + "\". ") +
                                                  MSG_PLEASE_TRY_AGAIN
                                                , false
                                                , true
                                            );

                                            Program.ExceptionControl(iaux);

                                            _password    = string.Empty;
                                            _salt        = string.Empty;
                                            _saltleaking = false;

                                            if (_without_iv)
                                                _blocksize = naux;

                                            --i;
                                            continue;
                                        }
                                    }

                                    break;
                            }

                            if (_raise)
                                throw e;

                            Messenger.Print
                            (
                                  Messenger.Icon.ERROR
                                , "An exception occurred while processing the file: \"" +
                                  Path.GetFileName(_overwrite ? ifn : ofn) + 
                                  "\". Exception message: " + e.Message
                                , false
                                , true
                            );

                            Program.ExceptionControl(iaux);
                        }
					}
					
					Messenger.Print(Messenger.Icon.INFORMATION, MSG_DONE);
                }

                catch (Exception e)
                {
                    Program.ShowBanner();

                    if (_percent < 100)
                        Program.Progress(1, 1, 0);

                    if (!string.IsNullOrEmpty(e.Message))
                    {
                        Messenger.Print(Messenger.Icon.ERROR, e.Message);
                        Console.WriteLine();
                    }

                    Environment.Exit(1);
                }
            }
        }
    }
}
