using System;
using System.Security.Cryptography;

using CryptoLib.CipherModes;

namespace CryptoLib.PaddingModes
{
	public abstract class PaddingModeImpl : ICryptoTransform
	{
		public bool CanReuseTransform{ get{ return true; } }
		public bool CanTransformMultipleBlocks{ get{ return true; } }

		private CipherModeImpl _cipher;
		private bool _resetOnFinalTransform = true;

		public CipherModeImpl Cipher{ get{ return _cipher; } }
		public bool ResetOnFinalTransform{ get{ return _resetOnFinalTransform; } set{ _resetOnFinalTransform = value; } }

		public int InputBlockSize{ get{ return _cipher.BlockSize; } }
		public int OutputBlockSize{ get{ return _cipher.BlockSize; } }

		protected PaddingModeImpl( CipherModeImpl cipher )
		{
			_cipher = cipher;
		}

		public int TransformBlock( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			if ( _cipher == null )
				throw new ObjectDisposedException( null );
			if ( inputBuffer == null )
				throw new ArgumentNullException( "inputBuffer" );
			if ( inputCount <= 0 || inputCount % InputBlockSize != 0 )
				throw new ArgumentException( "Invalid inputCount value", "inputCount" );
			if ( inputOffset < 0 || inputOffset + inputCount > inputBuffer.Length )
				throw new ArgumentException( "The sum of inputCount and inputOffset is greater than the length of the input buffer" );
			if ( outputBuffer == null )
				throw new ArgumentNullException( "outputBuffer" );

			return InternalTransform( inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset );
		}

		public byte[] TransformFinalBlock( byte[] inputBuffer, int inputOffset, int inputCount )
		{
			if ( _cipher == null )
				throw new ObjectDisposedException( null );
			if ( inputBuffer == null )
				throw new ArgumentNullException( "inputBuffer" );
			if ( inputCount < 0 )
				throw new ArgumentException( "Invalid inputCount value", "inputCount" );
			if ( inputOffset < 0 || inputOffset + inputCount > inputBuffer.Length )
				throw new ArgumentException( "The sum of inputCount and inputOffset is greater than the length of the input buffer" );

			byte[] data = InternalTransformFinal( inputBuffer, inputOffset, inputCount );

			if ( _resetOnFinalTransform )
				Cipher.Reset();

			return data;
		}

		protected virtual int InternalTransform( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
		{
			_cipher.Transform( inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset );
			return inputCount;
		}

		protected abstract byte[] InternalTransformFinal( byte[] inputBuffer, int inputOffset, int inputCount );

		public virtual void Dispose()
		{
			if ( _cipher != null )
			{
				_cipher.Dispose();
				_cipher = null;
			}
		}
	}
}