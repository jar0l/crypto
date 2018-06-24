using System;

using CryptoLib.BlockCiphers;

namespace CryptoLib.CipherModes
{
	public sealed class CTRImpl : CipherModeImpl
	{
		private byte[] _seed;
		private byte[] _counter;
		private byte[] _buffer;
		private int _bufferPosition;

		public CTRImpl( IBlockCipher cipher, byte[] seed ) : base( cipher )
		{
			_seed = (byte[]) seed.Clone();
			_counter = new byte[cipher.BlockSize];
			_buffer = new byte[cipher.BlockSize];
			_bufferPosition = _buffer.Length - 1;

			Buffer.BlockCopy( _seed, 0, _counter, 0, _seed.Length );
		}

		public override int BlockSize{ get{ return 1; } }

		private void IncreaseCounter()
		{
			for ( int i = _counter.Length - 1; i >= 0; i-- )
			{
				if ( ++_counter[i] != 0 )
					break;
			}
		}

		public override void Transform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			for ( int i = 0; i < inputCount; i++ )
			{
				if ( ++_bufferPosition >= _buffer.Length )
				{
					Cipher.Transform( _counter, 0, _buffer, 0 );
					_bufferPosition = 0;

					IncreaseCounter();
				}

				outputBuffer[outputOffset + i] = (byte)( inputBuffer[inputOffset + i] ^ _buffer[_bufferPosition] );
			}
		}

		public override void Reset()
		{
			Buffer.BlockCopy( _seed, 0, _counter, 0, _seed.Length );
			Array.Clear( _counter, _seed.Length, _counter.Length - _seed.Length );
			_bufferPosition = _buffer.Length - 1;
		}

		public override void Dispose()
		{
			if ( _seed != null )
			{
				Array.Clear( _seed, 0, _seed.Length );
				_seed = null;
			}
			if ( _counter != null )
			{
				Array.Clear( _counter, 0, _counter.Length );
				_counter = null;
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