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
 * http://www.jensign.com/opensslkey/opensslkey.cs
 * http://juliusdavies.ca/commons-ssl/src/java/org/apache/commons/ssl/OpenSSL.java
 * 
 */

using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace System.Security.Cryptography
{
    class OpenSSL
    {
        private const string MSG_WRONG_OSSL_DATA = "Wrong OpenSSL data!";

        //----------------------------------------------------------------------------------

        private static readonly byte[] _seqoid = 
        { 
              0x30, 0x0D, 0x06
            , 0x09, 0x2A, 0x86
            , 0x48, 0x86, 0xF7
            , 0x0D, 0x01, 0x01
            , 0x01, 0x05, 0x00 
        };

        //----------------------------------------------------------------------------------

        private static byte[] Decrypt (SymmetricAlgorithm sa, byte[] key, byte[] iv, byte[] data)
        {
            sa.Mode    = CipherMode.CBC;
            sa.Padding = PaddingMode.PKCS7;

            using (ICryptoTransform ct = sa.CreateDecryptor(key, iv))
            {
                using (MemoryStream ms = new MemoryStream(data))
                {
                    using (CryptoStream cs = new CryptoStream(ms, ct, CryptoStreamMode.Read))
                    {
                        using (MemoryStream bf = new MemoryStream())
                        {
                            byte[] d = new byte[1024];
                            for (int n; (n = cs.Read(d, 0, d.Length)) > 0; )
                                bf.Write(d, 0, n);

                            data = bf.ToArray();
                        }
                    }
                }
            }

            return data;
        }


        //----------------------------------------------------------------------------------

        private static bool CompareByteArray (byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            int i = 0;
            foreach (byte c in a)
                if (c != b[i++]) return false;

            return true;
        }

        //----------------------------------------------------------------------------------

        private static int GetSize (BinaryReader br)
        {
            if (br.ReadByte() != 0x02)
                return 0;

            int cn = br.ReadByte();

            if (cn == 0x81)
                cn = br.ReadByte();

            else if (cn == 0x82)
            {
                byte bh = br.ReadByte();
                byte bl = br.ReadByte();

                byte[] mod = { bl, bh, 0x00, 0x00 };
                cn = BitConverter.ToInt32(mod, 0);
            }

            while (br.ReadByte() == 0x00)
                cn -= 1;

            br.BaseStream.Seek(-1, SeekOrigin.Current);
            return cn;
        }


        //----------------------------------------------------------------------------------

        public static void SetPublicKey (RSACryptoServiceProvider rsa, byte[] data)
        {
            byte[] b;
            using (MemoryStream ms = new MemoryStream(data))
            {
                using (BinaryReader br = new BinaryReader(ms))
                {
                    int n = br.ReadUInt16();

                    if (n == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    else throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    b = br.ReadBytes(15);
                    if (!OpenSSL.CompareByteArray(b, OpenSSL._seqoid))
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if ((n = br.ReadUInt16()) == 0x8103)
                        br.ReadByte();

                    else if (n == 0x8203)
                        br.ReadInt16();

                    else throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if (br.ReadByte() != 0x00)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if ((n = br.ReadUInt16()) == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    else throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    byte lb = 0;
                    byte hb = 0;

                    if ((n = br.ReadUInt16()) == 0x8102)
                        lb = br.ReadByte();

                    else if (n == 0x8202)
                    {
                        hb = br.ReadByte();
                        lb = br.ReadByte();
                    }

                    else throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    byte[] mod = { lb, hb, 0x00, 0x00 };
                    n = BitConverter.ToInt32(mod, 0);

                    lb = br.ReadByte();
                    br.BaseStream.Seek(-1, SeekOrigin.Current);

                    if (lb == 0x00)
                    {
                        br.ReadByte();
                        --n;
                    }

                    b = br.ReadBytes(n);

                    if (br.ReadByte() != 0x02)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    RSAParameters p = new RSAParameters();

                    p.Modulus  = b;
                    p.Exponent = br.ReadBytes((int)br.ReadByte());
                    rsa.ImportParameters(p);
                }
            }
        }

        //----------------------------------------------------------------------------------

        public static void SetRsaPrivateKey (RSACryptoServiceProvider rsa, byte[] data)
        {
            using (MemoryStream ms = new MemoryStream(data))
            {
                using (BinaryReader br = new BinaryReader(ms))
                {
                    ushort un = br.ReadUInt16();

                    if (un == 0x8130)
                        br.ReadByte();

                    else if (un == 0x8230)
                        br.ReadInt16();

                    else throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if (br.ReadUInt16() != 0x0102)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if (br.ReadByte() != 0x00)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    RSAParameters p = new RSAParameters();

                    p.Modulus  = br.ReadBytes(OpenSSL.GetSize(br));
                    p.Exponent = br.ReadBytes(OpenSSL.GetSize(br));
                    p.D        = br.ReadBytes(OpenSSL.GetSize(br));
                    p.P        = br.ReadBytes(OpenSSL.GetSize(br));
                    p.Q        = br.ReadBytes(OpenSSL.GetSize(br));
                    p.DP       = br.ReadBytes(OpenSSL.GetSize(br));
                    p.DQ       = br.ReadBytes(OpenSSL.GetSize(br));
                    p.InverseQ = br.ReadBytes(OpenSSL.GetSize(br));

                    rsa.ImportParameters(p);
                }
            }
        }

        //----------------------------------------------------------------------------------

        public static void SetPrivateKey (RSACryptoServiceProvider rsa, byte[] data)
        {
            using (MemoryStream ms = new MemoryStream(data))
            {
                using (BinaryReader br = new BinaryReader(ms))
                {
                    int n = br.ReadUInt16();

                    if (n == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    else throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if (br.ReadByte() != 0x02)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if (br.ReadUInt16() != 0x0001)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    byte[] b = br.ReadBytes(15);
                    if (!OpenSSL.CompareByteArray(b, OpenSSL._seqoid))
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if (br.ReadByte() != 0x04)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if ((n = br.ReadByte()) == 0x81)
                        br.ReadByte();

                    else if (n == 0x82)
                        br.ReadUInt16();

                    Array.Clear(b, 0, b.Length);
                    b = br.ReadBytes((int)(ms.Length - ms.Position));

                    OpenSSL.SetRsaPrivateKey(rsa, b);
                    Array.Clear(b, 0, b.Length);
                }
            }
        }

        //----------------------------------------------------------------------------------

        public static void SetEncryptedPrivateKey
        (
              RSACryptoServiceProvider rsa
            , byte[]                   data
            , string                   password
        ){
            byte[] OIDpkcs5PBES2  = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D};
            byte[] OIDpkcs5PBKDF2 = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C};
            byte[] OIDdesEDE3CBC  = {0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07};

            using (MemoryStream ms = new MemoryStream(data))
            {
                using (BinaryReader br = new BinaryReader(ms))
                {
                    int n = br.ReadUInt16();
                    if (n == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    else throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if ((n = br.ReadUInt16()) == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    byte[] b = br.ReadBytes(11);
                    if (!OpenSSL.CompareByteArray(b, OIDpkcs5PBES2))
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    Array.Clear(b, 0, b.Length);

                    if ((n = br.ReadUInt16()) == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    if ((n = br.ReadUInt16()) == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    b = br.ReadBytes(11);
                    if (!OpenSSL.CompareByteArray(b, OIDpkcs5PBKDF2))
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    Array.Clear(b, 0, b.Length);

                    if ((n = br.ReadUInt16()) == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    if (br.ReadByte() != 0x04)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    byte[] salt = br.ReadBytes(br.ReadByte());

                    if (br.ReadByte() != 0x02)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    int iterations = 0;
                    if ((n = br.ReadByte()) == 1)
                        iterations = br.ReadByte();

                    else if (n == 2)
                        iterations = 256 * br.ReadByte() + br.ReadByte();

                    else throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if ((n = br.ReadUInt16()) == 0x8130)
                        br.ReadByte();

                    else if (n == 0x8230)
                        br.ReadInt16();

                    b = br.ReadBytes(10);
                    if (!OpenSSL.CompareByteArray(b, OIDdesEDE3CBC))
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    Array.Clear(b, 0, b.Length);

                    if (br.ReadByte() != 0x04)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    byte[] iv = br.ReadBytes(br.ReadByte());

                    if (br.ReadByte() != 0x04)
                        throw new CryptographicException(OpenSSL.MSG_WRONG_OSSL_DATA);

                    if ((n = br.ReadByte()) == 0x81)
                        n = br.ReadByte();

                    else if (n == 0x82)
                        n = 256 * br.ReadByte() + br.ReadByte();

                    data = br.ReadBytes(n);

                    Rfc2898DeriveBytes db = new Rfc2898DeriveBytes(password, salt, iterations);
                    byte[]             bk = db.GetBytes(24);

                    using (TripleDES td = TripleDES.Create())
                        b = OpenSSL.Decrypt(td, bk, iv, data);

                    OpenSSL.SetPrivateKey(rsa, b);

                    db.Reset();
                    Array.Clear(b, 0, b.Length);
                    Array.Clear(data, 0, data.Length);
                    Array.Clear(salt, 0, salt.Length);
                    Array.Clear(iv, 0, iv.Length);
                    Array.Clear(bk, 0, bk.Length);
                }
            }
        }

        //----------------------------------------------------------------------------------

        public static byte[] DecryptRsaPrivateKey 
        (
              string algoritm
            , string code
            , string password
            , byte[] data
        ){
            string dn = "DES";
            string an = string.Empty;
            int    ks = 0;
            int    bs = 0;
            int    fs = 0;

            if ((algoritm = algoritm.ToUpper()).StartsWith("AES"))
            {
                an = "Rijndael";
                bs = 128;
                fs = 128;
            }

            switch (algoritm)
            {
                case "DES-CBC":
                    an = dn;
                    ks = 64;
                    bs = 64;
                    break;

                case "DES-EDE3-CBC":
                    an = "TripleDES";
                    ks = 192;
                    bs = 64;
                    break;

                case "AES-128-CBC":
                    ks = 128;
                    break;

                case "AES-192-CBC":
                    ks = 192;
                    break;

                case "AES-256-CBC":
                    ks = 256;
                    break;

                default:
                    throw new CryptographicException("\"" + algoritm + "\" is not supported!");
            }

            using (SymmetricAlgorithm sa = SymmetricAlgorithm.Create(an))
            {
                sa.KeySize   = ks;
                sa.BlockSize = bs;

                ks /= 8; 

                if (fs > 0)
                    sa.FeedbackSize = fs;

                byte[] iv = new byte[code.Length / 2];

                for (int i = 0, l = iv.Length; i < l; ++i)
                    iv[i] = Convert.ToByte(code.Substring(i * 2, 2), 16);

                byte[] b, d, h, k, p = Encoding.ASCII.GetBytes(password);

                using (MD5 m = MD5.Create())
                {
                    if (algoritm.StartsWith(dn))                                                    // DES or 3DES
                    {
                        int n = 16;

                        k = new byte[p.Length + iv.Length];
                        h = new byte[k.Length + n];
                        d = new byte[32];

                        Array.Copy(p, k, p.Length);
                        Array.Copy(iv, 0, k, p.Length, iv.Length);
                        Array.Clear(p, 0, p.Length);

                        for (int i = 0; i < 2; ++i)
                        {
                            if (i == 0)
                                p = k;

                            else
                            {
                                Array.Copy(p, h, p.Length);
                                Array.Copy(k, 0, h, p.Length, k.Length);
                                Array.Clear(p, 0, p.Length);

                                p = h;
                            }

                            Array.Copy(p = m.ComputeHash(p), 0, d, i * n, p.Length);
                        }

                        Array.Clear(h, 0, h.Length);
                    }

                    else                                                                            // AES:
                    {
                        k = new byte[p.Length + 8];
                        h = new byte[ks + iv.Length];

                        Array.Copy(p, k, p.Length);
                        Array.Copy(iv, 0, k, p.Length, 8);                                          // Salt.

                        for (int n, i = 0, l = h.Length; i < l; )
                        {
                            d = m.ComputeHash(k);

                            if (d.Length > (n = l - i))
                            {
                                b = new byte[n];
                                Array.Copy(d, b, b.Length);
                                Array.Clear(d, 0, d.Length);
                                d = b;
                            }

                            Array.Copy(d, 0, h, i, d.Length);

                            if ((i += d.Length) < h.Length)
                            {
                                Array.Clear(k, 0, k.Length);
                                k = new byte[d.Length + p.Length + 8];

                                Array.Copy(d, k, d.Length);
                                Array.Copy(p, 0, k, d.Length, p.Length);
                                Array.Copy(iv, 0, k, d.Length + p.Length, 8);
                            }

                            Array.Clear(d, 0, d.Length);
                        }

                        d = h;
                    }
                }

                Array.Clear(k, 0, k.Length);
                k = new byte[ks];
                Array.Copy(d, k, k.Length);

                Array.Clear(d, 0, d.Length);
                Array.Clear(p, 0, p.Length);

                data = OpenSSL.Decrypt(sa, k, iv, data);

                Array.Clear(k, 0, k.Length);
                Array.Clear(iv, 0, iv.Length);
            }
            
            return data;
        }

        //----------------------------------------------------------------------------------

        public static byte[] GetRawData 
        (
              byte[]     src
            , string     key
            , ref string code
            , ref string algorithm
        ){
            string s = string.Empty;

            using (MemoryStream ms = new MemoryStream(src))
            {
                using (StreamReader sr = new StreamReader(ms))
                {
                    StringComparison sc = StringComparison.InvariantCultureIgnoreCase;
                    int              n  = -1;

                    while (sr.Peek() >= 0 && n == -1) 
                        n = sr.ReadLine().IndexOf("BEGIN " + key, sc);

                    if (n != -1)
                    {
                        string l;
                        while (sr.Peek() >= 0)
                        {
                            l = sr.ReadLine();
                            n = l.IndexOf("END " + key, sc);

                            if (n != -1)
                                break;

                            if (l.IndexOf("Proc-Type:", sc) != -1)
                            {
                                if (l.IndexOf("ENCRYPTED", sc) > (n = l.IndexOf('4')) && n != -1)
                                {
                                    string e = string.Format
                                    (
                                          "Unable to collect the \"{0}\" encrypted-info!"
                                        , key.ToLower()
                                    );

                                    while (sr.Peek() >= 0)
                                    {
                                        l = sr.ReadLine();
                                        n = l.IndexOf("DEK-Info:", sc);

                                        if (n != -1)
                                        {
                                            int i = n + 9;
                                            if ((n = l.IndexOf(',', i)) == -1)
                                                throw new CryptographicException(e);

                                            algorithm = l.Substring(i, n - i).Trim();
                                            if (string.IsNullOrEmpty(code = l.Substring(++n).Trim()))
                                                throw new CryptographicException(e);

                                            break;
                                        }
                                    }

                                    if (n == -1)
                                        throw new CryptographicException(e);
                                }

                                continue;
                            }

                            foreach (char c in " \a\b\t\v\f")
                                l = l.Replace(c.ToString(), string.Empty);

                            s += l;
                        }
                    }
                }
            }

            return string.IsNullOrEmpty(s) ? null : Convert.FromBase64String(s);
        }

        //----------------------------------------------------------------------------------

        public static byte[] GetRawData (byte[] src, string key)
        {
            string s = string.Empty;
            return OpenSSL.GetRawData(src, key, ref s, ref s);
        }

        //----------------------------------------------------------------------------------

        public static byte[] GetRawData
        (
              string     src
            , string     key
            , ref string code
            , ref string algorithm
        ){
            byte[] s = Encoding.ASCII.GetBytes(src);
            byte[] b = OpenSSL.GetRawData(s, key, ref code, ref algorithm);

            Array.Clear(s, 0, s.Length);
            return b;
        }

        //----------------------------------------------------------------------------------

        public static byte[] GetRawData (string src, string key)
        {
            string s = string.Empty;
            return OpenSSL.GetRawData(src, key, ref s, ref s);
        }
    }
}
