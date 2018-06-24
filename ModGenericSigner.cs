using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class ModGenericSigner
        : ISigner
    {
        private readonly IAsymmetricBlockCipher engine;
        private readonly IDigest digest;
        private bool forSigning;

        public ModGenericSigner(
            IAsymmetricBlockCipher	engine,
            IDigest					digest)
        {
            this.engine = engine;
            this.digest = digest;
        }

        public virtual string AlgorithmName
        {
            get { return "Generic(" + engine.AlgorithmName + "/" + digest.AlgorithmName + ")"; }
        }

        /**
        * initialise the signer for signing or verification.
        *
        * @param forSigning
        *            true if for signing, false otherwise
        * @param parameters
        *            necessary parameters.
        */
        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            this.forSigning = forSigning;

            AsymmetricKeyParameter k;
            if (parameters is ParametersWithRandom)
            {
                k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).Parameters;
            }
            else
            {
                k = (AsymmetricKeyParameter)parameters;
            }

            if (forSigning && k.IsPrivate)
                throw new InvalidKeyException("Verification requires public key."); 

            if (!forSigning && !k.IsPrivate)
                throw new InvalidKeyException("Signing requires private key.");

            Reset();
            engine.Init(forSigning, parameters);
        }

        /**
        * update the internal digest with the byte b
        */
        public virtual void Update(byte input)
        {
            digest.Update(input);
        }

        /**
        * update the internal digest with the byte array in
        */
        public virtual void BlockUpdate(byte[] input, int inOff, int length)
        {
            digest.BlockUpdate(input, inOff, length);
        }

        /**
        * Generate a signature for the message we've been loaded with using the key
        * we were initialised with.
        */
        public virtual byte[] GenerateSignature()
        {
            if (!forSigning)
                throw new InvalidOperationException("GenericSigner not initialised for signature generation.");

            byte[] hash = new byte[digest.GetDigestSize()];
            byte[] a, b = new byte[engine.GetInputBlockSize()];
            int    n;

            digest.DoFinal(hash, 0);
            using (MemoryStream dat = new MemoryStream(hash))
            {
                using (MemoryStream bf = new MemoryStream())
                {
                    while ((n = dat.Read(b, 0, b.Length)) > 0)
                    {
                        a = engine.ProcessBlock(b, 0, n);

                        bf.Write(a, 0, a.Length);
                        Array.Clear(a, 0, a.Length);
                    }

                    Array.Clear(b, 0, b.Length);
                    b = bf.ToArray();
                }
            }

            return b;
        }

        /**
        * return true if the internal state represents the signature described in
        * the passed in array.
        */
        public virtual bool VerifySignature(byte[] signature)
        {
            if (forSigning)
                throw new InvalidOperationException("GenericSigner not initialised for verification");

            byte[] sig, b = new byte[engine.GetInputBlockSize()];
            byte[] hash   = new byte[digest.GetDigestSize()];
            int    n;

            digest.DoFinal(hash, 0);

            try
            {
                using (MemoryStream dat = new MemoryStream(signature))
                {
                    using (MemoryStream bf = new MemoryStream())
                    {
                        while ((n = dat.Read(b, 0, b.Length)) > 0)
                        {
                            sig = engine.ProcessBlock(b, 0, n);

                            bf.Write(sig, 0, sig.Length);
                            Array.Clear(sig, 0, sig.Length);
                        }

                        Array.Clear(b, 0, b.Length);
                        sig = bf.ToArray();
                    }
                }

                // Extend with leading zeroes to match the digest size, if necessary.
                if (sig.Length < hash.Length)
                {
                    byte[] tmp = new byte[hash.Length];
                    Array.Copy(sig, 0, tmp, tmp.Length - sig.Length, sig.Length);
                    sig = tmp;
                }

                return Arrays.ConstantTimeAreEqual(sig, hash);
            }
            catch (Exception)
            {
                return false;
            }
        }

        public virtual void Reset()
        {
            digest.Reset();
        }
    }
}
