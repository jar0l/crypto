using System;
using System.Security.Cryptography;

namespace CryptoLib.SymmetricAlgorithms
{
	public abstract class Mars : SymmetricAlgorithm
	{
		private static readonly KeySizes[] _legalKeySizes = new KeySizes[] { new KeySizes( 128, 448, 32 ) };
		private static readonly KeySizes[] _legalBlockSizes = new KeySizes[] { new KeySizes( 128, 128, 0 ) };

		protected Mars()
		{
			this.LegalKeySizesValue = _legalKeySizes;
			this.LegalBlockSizesValue = _legalBlockSizes;

			this.KeySizeValue = 256;
			this.FeedbackSizeValue = this.BlockSizeValue = 128;
		}
	}
}