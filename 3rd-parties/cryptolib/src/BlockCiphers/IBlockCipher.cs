using System;

namespace CryptoLib.BlockCiphers
{
	public interface IBlockCipher : IDisposable
	{
		int BlockSize{ get; }
		bool Encryption{ get; }

		void Transform( byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset );
	}
}