using System;
using System.Security.Cryptography;

using CryptoLib.BlockCiphers;

namespace CryptoLib.CipherModes
{
	public abstract class CipherModeImpl : IDisposable
	{
		private IBlockCipher _cipher;

		public IBlockCipher Cipher{ get{ return _cipher; } }

		protected CipherModeImpl( IBlockCipher cipher )
		{
			_cipher = cipher;
		}

		public abstract int BlockSize{ get; }

		public abstract void Transform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset );

		public virtual void Reset()
		{
		}

		public virtual void Dispose()
		{
			if ( _cipher != null )
			{
				_cipher.Dispose();
				_cipher = null;
			}
		}
	}
}