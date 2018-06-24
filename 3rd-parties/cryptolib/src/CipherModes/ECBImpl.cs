using System;

using CryptoLib.BlockCiphers;

namespace CryptoLib.CipherModes
{
	public sealed class ECBImpl : CipherModeImpl
	{
		public ECBImpl( IBlockCipher cipher ) : base( cipher )
		{
		}

		public override int BlockSize{ get{ return Cipher.BlockSize; } }

		public override void Transform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			for ( int i = 0; i < inputCount; i += BlockSize )
				Cipher.Transform( inputBuffer, inputOffset + i, outputBuffer, outputOffset + i );
		}
	}
}