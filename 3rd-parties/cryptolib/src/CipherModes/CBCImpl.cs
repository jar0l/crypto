using System;

using CryptoLib.BlockCiphers;

namespace CryptoLib.CipherModes
{
	public sealed class CBCEncryptImpl : CipherModeImpl
	{
		private byte[] _iv;
		private byte[] _buffer;

		public CBCEncryptImpl( IBlockCipher cipher, byte[] iv ) : base( cipher )
		{
			_iv = (byte[]) iv.Clone();
			_buffer = new byte[cipher.BlockSize];

			Buffer.BlockCopy( _iv, 0, _buffer, 0, _iv.Length );
		}

		public override int BlockSize{ get{ return Cipher.BlockSize; } }

		public override void Transform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			for ( int i = 0; i < inputCount; i += BlockSize )
			{
				for ( int j = 0; j < _buffer.Length; j++ )
					_buffer[j] ^= inputBuffer[inputOffset + i + j];

				Cipher.Transform( _buffer, 0, _buffer, 0 );
				Buffer.BlockCopy( _buffer, 0, outputBuffer, outputOffset + i, _buffer.Length );
			}
		}

		public override void Reset()
		{
			Buffer.BlockCopy( _iv, 0, _buffer, 0, _iv.Length );
			Array.Clear( _buffer, _iv.Length, _buffer.Length - _iv.Length );
		}

		public override void Dispose()
		{
			if ( _iv != null )
			{
				Array.Clear( _iv, 0, _iv.Length );
				_iv = null;
			}
			if ( _buffer != null )
			{
				Array.Clear( _buffer, 0, _buffer.Length );
				_buffer = null;
			}
			base.Dispose();
		}
	}

	public sealed class CBCDecryptImpl : CipherModeImpl
	{
		private byte[] _iv;
		private byte[] _cipherBuffer;
		private byte[] _decryptBuffer;

		public CBCDecryptImpl( IBlockCipher cipher, byte[] iv ) : base( cipher )
		{
			_iv = (byte[]) iv.Clone();

			_cipherBuffer = new byte[cipher.BlockSize];
			_decryptBuffer = new byte[cipher.BlockSize];

			Buffer.BlockCopy( _iv, 0, _cipherBuffer, 0, _iv.Length );
		}

		public override int BlockSize{ get{ return Cipher.BlockSize; } }

		public override void Transform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			for ( int i = 0; i < inputCount; i += BlockSize )
			{
				Cipher.Transform( inputBuffer, inputOffset + i, _decryptBuffer, 0 );

				for ( int j = 0; j < _decryptBuffer.Length; j++ )
					_decryptBuffer[j] ^= _cipherBuffer[j];

				Buffer.BlockCopy( inputBuffer, inputOffset + i, _cipherBuffer, 0, _cipherBuffer.Length );
				Buffer.BlockCopy( _decryptBuffer, 0, outputBuffer, outputOffset + i, _decryptBuffer.Length );
			}
		}

		public override void Reset()
		{
			Buffer.BlockCopy( _iv, 0, _cipherBuffer, 0, _iv.Length );
			Array.Clear( _cipherBuffer, _iv.Length, _cipherBuffer.Length - _iv.Length );
		}

		public override void Dispose()
		{
			if ( _iv != null )
			{
				Array.Clear( _iv, 0, _iv.Length );
				_iv = null;
			}
			if ( _cipherBuffer != null )
			{
				Array.Clear( _cipherBuffer, 0, _cipherBuffer.Length );
				_cipherBuffer = null;
			}
			if ( _decryptBuffer != null )
			{
				Array.Clear( _decryptBuffer, 0, _decryptBuffer.Length );
				_decryptBuffer = null;
			}
			base.Dispose();
		}
	}
}