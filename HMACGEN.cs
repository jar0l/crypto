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
 * https://msdn.microsoft.com/en-us/library/vstudio/33kc9tdw(v=vs.100).aspx
 * https://hashlib.codeplex.com/
 */

using System.Security.Cryptography;
using HashLib;

namespace System.Security.Cryptography
{
    public class HMACGEN<T> : KeyedHashAlgorithm where T : IHash, new() 
    {
        private HashAlgorithm _h1        = null;
        private HashAlgorithm _h2        = null;
        private byte[]        _binner    = null;
        private byte[]        _bouter    = null;
        private bool          _bhashing;
        private short         _blocksize;

        //----------------------------------------------------------------------------------

        public HMACGEN ()
        {
            IHash h = new T();
 
            _h1 = new HashAlgorithmWrapper(h);
            _h2 = new HashAlgorithmWrapper(new T());

            Initialize();

            _blocksize    = (short)h.BlockSize;
            _binner       = new byte[_blocksize];
            _bouter       = new byte[_blocksize];
            HashSizeValue = _h1.HashSize;
        }

        //----------------------------------------------------------------------------------

        public HMACGEN (byte[] key): this()
        {
            Key = key;
        }

        //----------------------------------------------------------------------------------

        public string HashName  { get { return typeof(T).Name; } }
        public short  BlockSize { get { return _blocksize;     } }

        //----------------------------------------------------------------------------------

        public override byte[] Key
        {
            get { return (byte[])KeyValue.Clone(); }
            set
            {
                if (_bhashing)
                    throw new CryptographicException("Cannot change key during hash operation!");

                KeyValue = value.Length > _blocksize ? _h1.ComputeHash(value) : (byte[])value.Clone();

                int i;
                for (i = 0; i < _blocksize; i++)
                {
                    _binner[i] = 0x36;
                    _bouter[i] = 0x5C;
                }

                for (i = 0; i < KeyValue.Length; i++)
                {
                    _binner[i] ^= KeyValue[i];
                    _bouter[i] ^= KeyValue[i];
                }
            }
        }

        //----------------------------------------------------------------------------------

        public override void Initialize ()
        {
            _h1.Initialize();
            _h2.Initialize();
            _bhashing = false;
        }

        //----------------------------------------------------------------------------------

        protected override void HashCore (byte[] rgb, int ib, int cb)
        {
            if (!_bhashing)
            {
                _h1.TransformBlock(_binner, 0, _blocksize, _binner, 0);
                _bhashing = true;
            }

            _h1.TransformBlock(rgb, ib, cb, rgb, ib);
        }

        //----------------------------------------------------------------------------------

        protected override byte[] HashFinal ()
        {
            if (!_bhashing)
            {
                _h1.TransformBlock(_binner, 0, _blocksize, _binner, 0);
                _bhashing = true;
            }

            _h1.TransformFinalBlock(new byte[0], 0, 0);
            _h2.TransformBlock(_bouter, 0, _blocksize, _bouter, 0);
            _h2.TransformFinalBlock(_h1.Hash, 0, _h1.Hash.Length);
            _bhashing = false;

            return _h2.Hash;
        }

        //----------------------------------------------------------------------------------

        protected override void Dispose (bool disposing)
        {
            if (disposing)
            {
                if (_h1 != null)
                    ((IDisposable)_h1).Dispose();

                if (_h2 != null)
                    ((IDisposable)_h2).Dispose();

                if (_binner != null)
                    Array.Clear(_binner, 0, _binner.Length);

                if (_bouter != null)
                    Array.Clear(_bouter, 0, _bouter.Length);

                if (KeyValue != null)
                    Array.Clear(KeyValue, 0, KeyValue.Length);
            }

            base.Dispose(disposing);
        }
    }
}
