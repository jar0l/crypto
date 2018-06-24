using System;

using CryptoLib.CipherModes;

namespace CryptoLib.PaddingModes
{
	public sealed class PKCS7PadEncryptImpl : LengthPadEncryptImpl
	{
		public PKCS7PadEncryptImpl( CipherModeImpl cipher ) : base( cipher )
		{
		}

		protected override void FillBytes( byte[] buffer, int start, int count )
		{
			for ( int i = 0; i < count; i++ )
				buffer[start + i] = (byte)( count + 1 );
		}
	}
}