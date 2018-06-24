using System;
using System.Security.Cryptography;

using CryptoLib.CipherModes;

namespace CryptoLib.PaddingModes
{
	public abstract class LengthPadEncryptImpl : PaddingModeImpl
	{
		protected LengthPadEncryptImpl( CipherModeImpl cipher ) : base( cipher )
		{
		}

		protected abstract void FillBytes( byte[] buffer, int start, int count );

		protected override byte[] InternalTransformFinal( byte[] inputBuffer, int inputOffset, int inputCount )
		{
			int rem = inputCount % InputBlockSize;
			int evenCount = inputCount - rem;

			byte[] data = new byte[evenCount + InputBlockSize];

			Cipher.Transform( inputBuffer, inputOffset, evenCount, data, 0 );

			if ( rem > 0 )
				Buffer.BlockCopy( inputBuffer, inputOffset + evenCount, data, evenCount, rem );

			byte pad = (byte)( InputBlockSize - rem );

			FillBytes( data, evenCount + rem, pad - 1 );

			data[data.Length - 1] = pad;

			Cipher.Transform( data, evenCount, InputBlockSize, data, evenCount );

			return data;
		}
	}

	public sealed class LengthPadDecryptImpl : PaddingModeImpl
	{
		private byte[] _buffer;
		private bool _bufferData;

		public LengthPadDecryptImpl( CipherModeImpl cipher ) : base( cipher )
		{
			_bufferData = false;
		}

		protected override int InternalTransform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			if ( _bufferData )
			{
				Buffer.BlockCopy( _buffer, 0, outputBuffer, outputOffset, InputBlockSize );
				outputOffset += InputBlockSize;
			}

			int outCount = inputCount - InputBlockSize;
			int lastOffset = inputOffset + outCount;

			if ( outCount > 0 )
				Cipher.Transform( inputBuffer, inputOffset, outCount, outputBuffer, outputOffset );

			if ( _bufferData )
				outCount += InputBlockSize;

			if ( _buffer == null || _buffer.Length < InputBlockSize )
				_buffer = new byte[InputBlockSize];

			Cipher.Transform( inputBuffer, lastOffset, InputBlockSize, _buffer, 0 );
			_bufferData = true;

			return outCount;
		}

		protected override byte[] InternalTransformFinal( byte[] inputBuffer, int inputOffset, int inputCount )
		{
			int bufferLength = inputCount;
			if ( _bufferData )
				bufferLength += InputBlockSize;

			if ( _buffer == null || _buffer.Length < bufferLength )
			{
				byte[] newBuffer = new byte[bufferLength];

				if ( _bufferData )
					Buffer.BlockCopy( _buffer, 0, newBuffer, 0, InputBlockSize );

				_buffer = newBuffer;
			}

			if ( inputCount > 0 )
				Cipher.Transform( inputBuffer, inputOffset, inputCount, _buffer, bufferLength - inputCount );

			int pad = _buffer[bufferLength - 1];

			if ( pad < 1 || pad > InputBlockSize )
                throw new CryptographicException("Invalid data or padding size!");

			byte[] data = new byte[bufferLength - pad];
			Buffer.BlockCopy( _buffer, 0, data, 0, data.Length );

			_bufferData = false;

			return data;
		}

		public override void Dispose()
		{
			if ( _buffer != null )
			{
				Array.Clear( _buffer, 0, _buffer.Length );
				_buffer = null;
			}
			base.Dispose();
		}
	}
}