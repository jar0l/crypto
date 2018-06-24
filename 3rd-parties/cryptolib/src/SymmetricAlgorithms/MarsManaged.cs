using System;
using System.Security.Cryptography;

using CryptoLib.BlockCiphers;

namespace CryptoLib.SymmetricAlgorithms
{
	public sealed class MarsManaged : Mars
	{
		public MarsManaged()
		{
		}

		private ICryptoTransform CreateCryptoTransform( byte[] rgbKey, byte[] rgbIV, bool encrypt )
		{
			if ( rgbKey == null )
				rgbKey = this.Key;
			else if ( !ValidKeySize( rgbKey.Length * 8 ) )
				throw new ArgumentException( "Invalid key size" );

			if ( rgbIV != null && rgbIV.Length * 8 != BlockSize )
				throw new ArgumentException( "Invalid IV size" );

			MarsCipher cipher = new MarsCipher( rgbKey, Helper.ShouldEncrypt( this, encrypt ) );

			return Helper.CreateCryptoTransform( this, cipher, encrypt, rgbIV );
		}

		public override ICryptoTransform CreateEncryptor( byte[] rgbKey, byte[] rgbIV )
		{
			return CreateCryptoTransform( rgbKey, rgbIV, true );
		}

		public override ICryptoTransform CreateDecryptor( byte[] rgbKey, byte[] rgbIV )
		{
			return CreateCryptoTransform( rgbKey, rgbIV, false );
		}

		public override void GenerateKey()
		{
			KeyValue = new byte[KeySizeValue / 8];
			Helper.GetRandomBytes( KeyValue );
		}

		public override void GenerateIV()
		{
			IVValue = new byte[BlockSizeValue / 8];
			Helper.GetRandomBytes( IVValue );
		}
	}
}