using System;

using CryptoLib.BlockCiphers;

namespace CryptoLib.CipherModes
{
	public sealed class OFBImpl : CipherModeImpl
	{
		private byte[] _iv;
		private byte[] _buffer;
		private int _bufferPosition;

		public OFBImpl( IBlockCipher cipher, byte[] iv ) : base( cipher )
		{
			_iv = (byte[]) iv.Clone();
			_buffer = new byte[cipher.BlockSize];
			_bufferPosition = _buffer.Length - 1;

			Buffer.BlockCopy( _iv, 0, _buffer, 0, _iv.Length );
		}

		public override int BlockSize{ get{ return 1; } }

		public override void Transform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			for ( int i = 0; i < inputCount; i++ )
			{
				if ( ++_bufferPosition >= _buffer.Length )
				{
					Cipher.Transform( _buffer, 0, _buffer, 0 );
					_bufferPosition = 0;
				}

				outputBuffer[outputOffset + i] = (byte)( inputBuffer[inputOffset + i] ^ _buffer[_bufferPosition] );
			}
		}

		public override void Reset()
		{
			Buffer.BlockCopy( _iv, 0, _buffer, 0, _iv.Length );
			Array.Clear( _buffer, _iv.Length, _buffer.Length - _iv.Length );
			_bufferPosition = _buffer.Length - 1;
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
}