using System;
using System.Security.Cryptography;

using CryptoLib.BlockCiphers;
using CryptoLib.CipherModes;
using CryptoLib.PaddingModes;

namespace CryptoLib
{
	internal sealed class Helper
	{
		private Helper() { }

		[ThreadStatic]
		private static RandomNumberGenerator _rng;

		internal static void GetRandomBytes( byte[] data )
		{
			if ( _rng == null )
				_rng = RandomNumberGenerator.Create();

			_rng.GetBytes( data );
		}

		internal static void GetRandomBytes( byte[] data, int start, int count )
		{
			byte[] randomBuffer = new byte[count];
			GetRandomBytes( randomBuffer );

			Buffer.BlockCopy( randomBuffer, 0, data, start, count );
		}

		internal static bool ShouldEncrypt( SymmetricAlgorithm algorithm, bool encrypt )
		{
			return encrypt || algorithm.Mode == CipherMode.CFB || algorithm.Mode == CipherMode.OFB;
		}

		internal static ICryptoTransform CreateCryptoTransform( SymmetricAlgorithm algorithm, IBlockCipher cipher, bool encrypt, byte[] iv )
		{
			CipherModeImpl modeImpl;

			switch ( algorithm.Mode )
			{
				case CipherMode.ECB:
				{
					modeImpl = new ECBImpl( cipher );

					break;
				}
				case CipherMode.CBC:
				{
					if ( iv == null )
						iv = algorithm.IV;

					if ( encrypt )
						modeImpl = new CBCEncryptImpl( cipher, iv );
					else
						modeImpl = new CBCDecryptImpl( cipher, iv );

					break;
				}
				case CipherMode.CFB:
				{
					if ( iv == null )
						iv = algorithm.IV;

					int feedbackBytes = algorithm.FeedbackSize / 8;
					if ( algorithm.FeedbackSize <= 0 || algorithm.FeedbackSize % 8 != 0 || feedbackBytes > cipher.BlockSize )
						throw new CryptographicException( "Invalid feedback size" );

					if ( encrypt )
						modeImpl = new CFBEncryptImpl( cipher, feedbackBytes, iv );
					else
						modeImpl = new CFBDecryptImpl( cipher, feedbackBytes, iv );

					break;
				}
				case CipherMode.OFB:
				{
					if ( iv == null )
						iv = algorithm.IV;

					modeImpl = new OFBImpl( cipher, iv );

					break;
				}
				default:
				{
					throw new CryptographicException( "Unsupported cipher mode" );
				}
			}

			switch ( algorithm.Padding )
			{
                /*
				case PaddingMode.None:
				{
					return new NoPadImpl( modeImpl );
				}
				case PaddingMode.Zeros:
				{
					if ( encrypt )
						return new ZerosPadEncryptImpl( modeImpl );
					else
						return new NoPadImpl( modeImpl );
				}
                */

				case PaddingMode.PKCS7:
				{
					if ( encrypt )
						return new PKCS7PadEncryptImpl( modeImpl );
					else
						return new LengthPadDecryptImpl( modeImpl );
				}

				default:
				{
					throw new CryptographicException( "Unsupported padding mode" );
				}
			}
		}

		internal static uint RotateLeft( uint value, int count )
		{
			return ( value << count ) | ( value >> (32 - count) );
		}

		internal static uint RotateRight( uint value, int count )
		{
			return ( value << (32 - count) | value >> count );
		}

		internal static ulong RotateLeft( ulong value, int count )
		{
			return ( value << count ) | ( value >> (64 - count) );
		}

		internal static ulong RotateRight( ulong value, int count )
		{
			return ( value << (64 - count) | value >> count );
		}

		internal static uint ToLEUInt32( byte[] value, int startIndex )
		{
			if ( BitConverter.IsLittleEndian )
				return BitConverter.ToUInt32( value, startIndex );
			else
				return (uint)( value[startIndex] | value[startIndex + 1] << 8 | value[startIndex + 2] << 16 | value[startIndex + 3] << 24 );
		}

		internal static uint ToBEUInt32( byte[] value, int startIndex )
		{
			if ( BitConverter.IsLittleEndian )
				return (uint)( value[startIndex] << 24 | value[startIndex + 1] << 16 | value[startIndex + 2] << 8 | value[startIndex + 3] );
			else
				return BitConverter.ToUInt32( value, startIndex );
		}

		internal static ulong ToBEUInt64( byte[] value, int startIndex )
		{
			if ( BitConverter.IsLittleEndian )
				return (ulong) value[startIndex] << 56 | (ulong) value[startIndex + 1] << 48 | (ulong) value[startIndex + 2] << 40 | (ulong) value[startIndex + 3] << 32
					| (ulong) value[startIndex + 4] << 24 | (ulong) value[startIndex + 5] << 16 | (ulong) value[startIndex + 6] << 8 | (ulong) value[startIndex + 7];
			else
				return BitConverter.ToUInt64( value, startIndex );
		}

		internal static void ToLEBytes( uint value, byte[] output, int offset )
		{
			output[offset    ] = (byte)( value       );
			output[offset + 1] = (byte)( value >> 8  );
			output[offset + 2] = (byte)( value >> 16 );
			output[offset + 3] = (byte)( value >> 24 );
		}

		internal static void ToBEBytes( uint value, byte[] output, int offset )
		{
			output[offset    ] = (byte)( value >> 24 );
			output[offset + 1] = (byte)( value >> 16 );
			output[offset + 2] = (byte)( value >> 8  );
			output[offset + 3] = (byte)( value       );
		}

		internal static void ToLEBytes( ulong value, byte[] output, int offset )
		{
			output[offset    ] = (byte)( value       );
			output[offset + 1] = (byte)( value >>  8 );
			output[offset + 2] = (byte)( value >> 16 );
			output[offset + 3] = (byte)( value >> 24 );
			output[offset + 4] = (byte)( value >> 32 );
			output[offset + 5] = (byte)( value >> 40 );
			output[offset + 6] = (byte)( value >> 48 );
			output[offset + 7] = (byte)( value >> 56 );
		}

		internal static void ToBEBytes( ulong value, byte[] output, int offset )
		{
			output[offset    ] = (byte)( value >> 56 );
			output[offset + 1] = (byte)( value >> 48 );
			output[offset + 2] = (byte)( value >> 40 );
			output[offset + 3] = (byte)( value >> 32 );
			output[offset + 4] = (byte)( value >> 24 );
			output[offset + 5] = (byte)( value >> 16 );
			output[offset + 6] = (byte)( value >> 8  );
			output[offset + 7] = (byte)( value       );
		}
	}
}