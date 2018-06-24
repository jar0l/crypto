using System;

using CryptoLib.BlockCiphers;

namespace CryptoLib.CipherModes
{
	public sealed class CFBEncryptImpl : CipherModeImpl
	{
		private readonly int _feedback;
		private byte[] _iv;
		private byte[] _register;
		private byte[] _buffer;

		public CFBEncryptImpl( IBlockCipher cipher, int feedback, byte[] iv ) : base( cipher )
		{
			_feedback = feedback;
			_iv = (byte[]) iv.Clone();
			_register = new byte[cipher.BlockSize];
			_buffer = new byte[cipher.BlockSize];

			Buffer.BlockCopy( _iv, 0, _register, 0, _iv.Length );
		}

		public override int BlockSize{ get{ return _feedback; } }

		public override void Transform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			for ( int i = 0; i < inputCount; i += _feedback )
			{
				Cipher.Transform( _register, 0, _buffer, 0 );

				for ( int j = 0; j < _feedback; j++ )
					outputBuffer[outputOffset + i + j] = (byte)( inputBuffer[inputOffset + i + j] ^ _buffer[j] );

				Buffer.BlockCopy( _register, _feedback, _register, 0, _register.Length - _feedback );
				Buffer.BlockCopy( outputBuffer, outputOffset + i, _register, _register.Length - _feedback, _feedback );
			}
		}

		public override void Reset()
		{
			Buffer.BlockCopy( _iv, 0, _register, 0, _iv.Length );
			Array.Clear( _register, _iv.Length, _register.Length - _iv.Length );
		}

		public override void Dispose()
		{
			if ( _iv != null )
			{
				Array.Clear( _iv, 0, _iv.Length );
				_iv = null;
			}
			if ( _register != null )
			{
				Array.Clear( _register, 0, _register.Length );
				_register = null;
			}
			if ( _buffer != null )
			{
				Array.Clear( _buffer, 0, _buffer.Length );
				_buffer = null;
			}
			base.Dispose();
		}
	}

	public sealed class CFBDecryptImpl : CipherModeImpl
	{
		private readonly int _feedback;
		private byte[] _iv;
		private byte[] _register;
		private byte[] _buffer;

		public CFBDecryptImpl( IBlockCipher cipher, int feedback, byte[] iv ) : base( cipher )
		{
			_feedback = feedback;
			_iv = (byte[]) iv.Clone();
			_register = new byte[cipher.BlockSize];
			_buffer = new byte[cipher.BlockSize];

			Buffer.BlockCopy( _iv, 0, _register, 0, _iv.Length );
		}

		public override int BlockSize{ get{ return _feedback; } }

		public override void Transform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			for ( int i = 0; i < inputCount; i += _feedback )
			{
				Cipher.Transform( _register, 0, _buffer, 0 );

				Buffer.BlockCopy( _register, _feedback, _register, 0, _register.Length - _feedback );
				Buffer.BlockCopy( inputBuffer, inputOffset + i, _register, _register.Length - _feedback, _feedback );

				for ( int j = 0; j < _feedback; j++ )
					outputBuffer[outputOffset + i + j] = (byte)( inputBuffer[inputOffset + i + j] ^ _buffer[j] );
			}
		}

		public override void Reset()
		{
			Buffer.BlockCopy( _iv, 0, _register, 0, _iv.Length );
			Array.Clear( _register, _iv.Length, _register.Length - _iv.Length );
		}

		public override void Dispose()
		{
			if ( _iv != null )
			{
				Array.Clear( _iv, 0, _iv.Length );
				_iv = null;
			}
			if ( _register != null )
			{
				Array.Clear( _register, 0, _register.Length );
				_register = null;
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