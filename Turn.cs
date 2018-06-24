/*
MIT License

Copyright (c) 2018 José A. Rojo L.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System;
using System.Collections.Generic;
using System.Text;

namespace crypto
{
    class Turn
    {
        public static bool ToByte (string value, ref byte pointer)
        {
            try
            {
                pointer = Convert.ToByte(value);
                return true;
            }

            catch (Exception)
            {
                return false;
            }
        }

        public static bool ToInt16 (string value, ref short pointer)
        {
            try
            {
                pointer = Convert.ToInt16(value);
                return true;
            }

            catch (Exception)
            {
                return false;
            }
        }

        public static bool ToInt32 (string value, ref int pointer)
        {
            try
            {
                pointer = Convert.ToInt32(value);
                return true;
            }

            catch (Exception)
            {
                return false;
            }
        }

        public static bool ToInt64 (string value, ref long pointer)
        {
            try
            {
                pointer = Convert.ToInt64(value);
                return true;
            }

            catch (Exception)
            {
                return false;
            }
        }
    }
}
