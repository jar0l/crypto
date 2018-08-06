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
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Collections.Generic;

#if !NETCOREAPP2_0
    using System.Media;
#endif

//---------------------------------------------------------------------------------

namespace Jarol.Console
{
    class Messenger
    {
        //----------------------------------------------------------------------------------

        public struct Formated
        {
            public string         message;
            public ConsoleColor[] foreground;
            public ConsoleColor[] background;
        }

        //-------------------------------------------------------------------------

        public static char ColorChar = '\r';
        public static bool Clean     = true;

        //-------------------------------------------------------------------------

        public enum Icon
        {
              INFORMATION
            , QUESTION
            , WARNING
            , ERROR
            , UNKNOWN
        };

        //-------------------------------------------------------------------------

        public enum Frame
        {
              SIMPLE
            , DOUBLE
            , EXTRA
        };

        //-------------------------------------------------------------------------

        public static int MaxBufferWidth
        {
            get 
            {
                int n = 80;
                
                if (System.Console.WindowWidth > 0)
                    n = System.Console.WindowWidth;

                else if (System.Console.BufferWidth > 0)
                    n = System.Console.BufferWidth;

                return n;
            }
        }
        //-------------------------------------------------------------------------

        private static int Align (ref string s, int i, int m, byte a)
        {
            string p = " ";
            int    n = i;

            int z = s.Length;

            while (n > 0 && s[n] != '\n')
                --n;

            if (s[n] == '\n')
                ++n;

            int l = i - n;
            int x = m - l;
            int j = x;

            if (x < m) switch (a)
            {
                case 0:                                                                 // left.
                    break;

                case 1:                                                                 // rigth.
                    while (x > 0)
                    {
                        s = s.Insert(n, p);

                        ++i;
                        --x;
                    }
                    break;

                case 2:                                                                 // Center.
                    for (x /= 2; x > 0; --x)
                    {
                        s = s.Insert(n, p);
                        ++i;
                    }

                    break;

                case 3:                                                                 // Justify.
                    n = i;
                    while (x > 0)
                    {
                        while (--n > 0 && s[n] != ' ')
                            if (s[n] == '\n')
                                break;

                        if (n < 1 || s[n] == '\n')
                        {
                            if (x == j)
                                break;

                            n = i;
                        }

                        else
                        {
                            s = s.Insert(n, p);

                            ++i;
                            --x;
                        }
                    }
                    break;
            }

            return i;
        }
        //-------------------------------------------------------------------------

        private static bool CheckDataFormat (string s, int i, int j = -1)
        {
            switch (s[i])
            { 
                case '{':
                    if (j < 0)
                        return true;

                    return s[j] == '}';

                case '[':
                    if (j < 0)
                        return true;

                    return s[j] == ']';

                default:
                    return false;
            }
        }

        //-------------------------------------------------------------------------

        private static int CheckDataFormat (ref char c, int i, string s)
        {
            int l = s.Length;

            do
            {
                if (++i >= l)
                    return -1;
            }
            while (s[i] == ' ');
                

            if (((c = s[i]) == 't' || c == 'f' || c == 'b' || c == 'a') && s[++i] == ':')
                return i;

            return -1;
        }

        //-------------------------------------------------------------------------

        private static Formated Format 
        (
              string msg
            , int    mbw    = -1 /* MaxBufferWidth*/
            , int    offset = 0
        ){
            Formated           r = new Formated();
            List<ConsoleColor> f = new List<ConsoleColor>();
            List<ConsoleColor> b = new List<ConsoleColor>();
            bool               d = false;
            bool               x = false;
            bool               y = false;
            byte               a = 0;
            char               c = '\0';
            string             e = "Invalid console color!";
            
            f.Add(System.Console.ForegroundColor);
            b.Add(System.Console.BackgroundColor);

            if (mbw < 0)
                mbw = MaxBufferWidth - offset;

            msg += '\n';
            for (int n, l = mbw, i = 0, j = 0, k = 0, s = 0, t = 0, m = 0, p = 0; i < msg.Length; ++i)
            {
                if (Messenger.CheckDataFormat(msg, i))
                {
                    n = i;

                    do
                    {
                        if ((n = Messenger.CheckDataFormat(ref c, n, msg)) != -1)
                        {
                            m = msg.Length;
                            while (++n < m && msg[n] == ' ');

                            if (n >= m)
                                break;

                            for (j = n + 1, p = j + 3; j < p && j < m; ++j)
                            {
                                if (msg[j] == ',' || Messenger.CheckDataFormat(msg, i, j))
                                {
                                    m = Convert.ToInt32(msg.Substring(n, j - n).TrimEnd(null));

                                    switch (c)
                                    {
                                        case 't':
                                            t = m;
                                            break;

                                        case 'f':
                                            if (m < 0 || m > 15)
                                                throw new Exception(e);

                                            f.Add((ConsoleColor)m);
                                            d = true;
                                            break;

                                        case 'b':
                                            if (m < 0 || m > 15)
                                                throw new Exception(e);

                                            b.Add((ConsoleColor)m);
                                            d = true;
                                            break;

                                        case 'a':
                                            a = (byte)m;
                                            break;
                                    }

                                    if (msg[j] == ',')
                                        n = j;

                                    else
                                    {
                                        msg = msg.Remove(i, ++j - i);

                                        if (d)
                                        {
                                            if (i == 0)
                                            {
                                                f.RemoveAt(0);
                                                b.RemoveAt(0);
                                            }

                                            if ((m = msg.Length) > 0)
                                            {
                                                n = i;
                                                while (n < m && msg[n] == '\n')
                                                    ++n;
                                                
                                                j = n + 1;
                                                c = '\r';

                                                if (n < --m && msg[n] != c && (n == 0 || msg[n - 1] != c) && (j >= ++m || msg[j] != c))
                                                    msg = msg.Insert(n, c.ToString());
                                            }
                                        }

                                        if (t == 0 && x)
                                        {
                                            msg = msg.Insert(i, "\n");
                                            x   = false;
                                        }

                                        j = 0;
                                        d = false;
                                        --i;

                                        if (y)
                                        {
                                            y = false;
                                            --i;
                                        }
                                    }

                                    break;
                                }
                            }
                        }
                    }

                    while (j > 0 && j != p);
                }

                else if (msg[i] == '\n')
                {
                    i = Messenger.Align(ref msg, i, mbw, a);

                    if (++i >= (n = msg.Length))
                        break;

                    while (i < n && msg[i] == '\n')
                        ++i;

                    if (i >= n)
                        break;

                    if (Messenger.CheckDataFormat(msg, i) && Messenger.CheckDataFormat(ref c, i, msg) != -1)
                    {
                        --i;

                        y = true;
                        continue;
                    }

                    for (n = i, m = n + t; n < m; ++n)
                        if (msg[n] != ' ') msg = msg.Insert(n, " ");

                    l = --i + mbw;
                }

                else if (i < l)
                {
                    if (msg[i] == ' ')
                        s = i;

                    else if (msg[i] == Path.DirectorySeparatorChar)
                    {
                        if (Path.DirectorySeparatorChar != '\\' && msg[i - 1] == '\\')
                            msg = msg.Remove(i - 1, 1);

                        else if (msg[i + 1] == '\\')
                            msg = msg.Remove(i, 1);

                        else k = i + 1;
                    }

                    else if (msg[i] == '\t')
                    {
                        msg = msg.Remove(i, 1);

                        for (n = 0; n < 8; ++n)
                            msg = msg.Insert(i, " ");
                    }

                    else if (msg[i] == '\r' || msg[i] == '\a')
                        ++l;
                }

                else
                {
                    n = i - ((mbw / 2) + 5);                                   // Max. word len.

                    if (s > 0 && n < s && s > k)
                    {
                        msg = msg.Remove(s, 1);
                        msg = msg.Insert(s, "\n");
                        i   = --s;
                        k   = s = 0;
                        x   = true;
                    }

                    else if (k > 0 && n < k && k > s)
                    {
                        msg = msg.Insert(k, "\n");
                        i   = --k;
                        k   = s = 0;
                    }
                    
                    else
                    {
                        msg = msg.Insert(--i, "\n");
                        --i;
                    }
                }
            }

            r.message = msg.Remove(msg.Length - 1);

            if (f.Count < 1)
                r.foreground = null;

            else
            {
                r.foreground = f.ToArray();
                f.Clear();
            }

            if (b.Count < 1)
                r.background = null;

            else
            {
                r.background = b.ToArray();
                b.Clear();
            }

            return r;
        }

        //-------------------------------------------------------------------------

        public static void Print
        (
              string         msg											        // Message.
            , ConsoleColor[] fclr										            // Foreground colors.
            , ConsoleColor[] bclr											        // Background colors.
            , bool           format = false
        ){
            if (format)
            {
                Formated f = Messenger.Format(msg);
                msg = f.message;

                if (fclr == null)
                    fclr = f.foreground;

                if (bclr == null)
                    bclr = f.background;
            }

            string[] s = msg.Split(ColorChar);
            string   v = Environment.GetEnvironmentVariable("TERM");                // http://fedoraproject.org/wiki/Features/256_Color_Terminals
			bool     b = v == null || v.IndexOf("256") == -1;
            int      m = 0;
            int      n = 0;

            if (fclr != null)
                n = fclr.Length;

            if (bclr != null)
                m = bclr.Length;

            for (int i = 0, l = s.Length; i < l; ++i)
            {
                if (b)
                {
                    if (i < n && fclr[i] != System.Console.ForegroundColor)
                        System.Console.ForegroundColor = fclr[i];

                    if (i < m && bclr[i] != System.Console.BackgroundColor)
                        System.Console.BackgroundColor = bclr[i];
                }

                System.Console.Write(s[i]);
            }

            System.Console.ResetColor();

            if (Clean)
            {
                if (n > 0) Array.Clear(fclr, 0, n);
                if (m > 0) Array.Clear(bclr, 0, m);
            }
        }

        //-------------------------------------------------------------------------

        public static void Print (string msg, ConsoleColor[] fclr, bool format = false)
        {
            Messenger.Print(msg, fclr, null, format);
        }

        //-------------------------------------------------------------------------

        public static void Print
        (
              string       msg                                                      // Message.
            , ConsoleColor fclr												        // Foreground colors.
            , ConsoleColor bclr												        // Background colors.
            , bool         format = false
        ){
            bool b = Clean;
            Clean  = true;

            Messenger.Print
            (
                  msg
                , new ConsoleColor[] { fclr }
                , new ConsoleColor[] { bclr }
                , format
            );

            Clean = b;
        }

        //-------------------------------------------------------------------------

        public static void Print
        (
              string       msg                                                      // Message.
            , ConsoleColor fclr												        // Foreground colors.
            , bool         format = false
        ){
            bool b = Clean;
            Clean  = true;

            Messenger.Print(msg, new ConsoleColor[] { fclr }, format);
            Clean = b;
        }

        //-------------------------------------------------------------------------

        public static void Print (string msg)
        {
            bool b = Clean;
            Clean  = true;

            Messenger.Print(msg, null, true);
            Clean = b;
        }

        //-------------------------------------------------------------------------

        public static ConsoleKey Print
        (
              Icon           icn
            , string         msg                                                    // Message.
            , ConsoleKey[]   cks                                                    // Response keys.
            , bool           bss	    											// System sounds ('\a').
            , bool           bnl												    // New line.
        ){
            Formated _f = Messenger.Format("#### {t:6}" + msg, -1, 1);
            bool     _b = Clean;

            Clean = true;
            msg   = _f.message.Remove(0, 5);

            if (_f.foreground != null)
                Array.Clear(_f.foreground, 0, _f.foreground.Length);

            if (_f.background != null)
                Array.Clear(_f.background, 0, _f.background.Length);

            int i, n, f;
            while ((i = msg.IndexOf(ColorChar)) != -1)
                msg = msg.Remove(i, 1);

            StringBuilder  sb = new StringBuilder("\n [");
            ConsoleKeyInfo ki = new ConsoleKeyInfo();
            ConsoleColor[] cc;

            #if !NETCOREAPP2_0
                if (bss && Path.DirectorySeparatorChar == '\\')
                    SystemSounds.Beep.Play();
            #endif

            switch (icn)
            {
                case Icon.INFORMATION:
                    sb.Append('i');

                    cc = new ConsoleColor[] 
                    {
                          ConsoleColor.DarkGreen
                        , ConsoleColor.Gray
                    };
                    break;

                case Icon.QUESTION:
                    sb.Append('?');

                    cc = new ConsoleColor[] 
                    {
                          ConsoleColor.DarkCyan
                        , ConsoleColor.White
                    };
                    break;

                case Icon.WARNING:
                    sb.Append('!');

                    cc = new ConsoleColor[] 
                    {
                          ConsoleColor.Yellow
                        , ConsoleColor.White
                    };
                    break;

                case Icon.ERROR:
                    sb.Append('x');

                    cc = new ConsoleColor[] 
                    {
                          ConsoleColor.Red
                        , ConsoleColor.Yellow
                    };
                    break;

                default:
                    sb.Append('-');

                    cc = new ConsoleColor[] 
                    {
                          ConsoleColor.DarkYellow
                        , ConsoleColor.DarkGray
                    };
                    break;
            }

            sb.Append("]:");
            sb.Append(ColorChar);
            sb.Append(' ');
            sb.Append(msg);

            Messenger.Print(sb.ToString(), cc);

            if (cks != null && cks.Length > 0)
            {
                cc = new ConsoleColor[(cks.Length * 2) + 1];
                sb = new StringBuilder(" [");
                
                cc[0] = ConsoleColor.Gray;

                for (i = 0, n = cks.Length - 1, f = 1; i < cks.Length; i++)
                {
                    sb.Append(ColorChar);
                    sb.Append(cks[i].ToString());
                    sb.Append(ColorChar);
                    sb.Append(i != n ? ", " : "]:");

                    cc[f++] = ConsoleColor.Yellow;
                    cc[f++] = ConsoleColor.DarkGray;
                }

                cc[cc.Length - 1] = ConsoleColor.Gray;
                Messenger.Print(sb.ToString(), cc);

                bool b = false;

                do
                {
                    ki = System.Console.ReadKey(true);

                    foreach (ConsoleKey ck in cks)
                        if ((b = ki.Key == ck))
                            break;
                }
                while (!b);
            }

            if (bnl && msg.IndexOf('\n') != -1)
            {
                i = msg.Length - 1;
                n = i - 1;

                if (i < 1 || n < 1 || msg[i] != '\n' || msg[n] != '\n')
                    System.Console.WriteLine();
            }

            if ((Clean = _b) && cks != null)
                Array.Clear(cks, 0, cks.Length);

            return ki.Key;
        }

        //-------------------------------------------------------------------------

        public static ConsoleKey Print 
        (
              Icon         icn
            , string       msg
            , ConsoleKey[] cks
            , bool         bss
        ){
            return Messenger.Print(icn, msg, cks, bss, false);
        }

        //-------------------------------------------------------------------------

        public static void Print (Icon icn, string msg, bool bss, bool bnl)
        {
            Messenger.Print(icn, msg, null, bss, bnl);
        }

        //-------------------------------------------------------------------------

        public static void Print (Icon icn, string msg, bool bss)
        {
            Messenger.Print(icn, msg, null, bss, false);
        }

        //-------------------------------------------------------------------------

        public static void Print (Icon icn, string msg)
        {
            Messenger.Print(icn, msg, null, false, false);
        }

        //-------------------------------------------------------------------------

        public static void Print
        (
              char[]       chrs                                                  // Frame chars.
            , string       msg
            , ConsoleColor fclr                                                  // Frame color.
            , ConsoleColor tclr                                                  // Text color.
            , bool         bcwa                                                  // Console width adjust.
        ){
            if (chrs == null || chrs.Length < 1)
                throw new Exception("The character frame can't be null!");

            int  l = chrs.Length;
            bool b = Clean;
            Clean  = true;

            if (l < 7)
            {
                char c = chrs[0];
                chrs   = new char[7];

                for (int i = 0; i < 7; ++i)
                    chrs[i] = c;
            }

            Formated f = Messenger.Format(msg, (l = MaxBufferWidth - 3) - 1);
            msg = f.message;

            if (f.foreground != null)
                Array.Clear(f.foreground, 0, f.foreground.Length);

            if (f.background != null)
                Array.Clear(f.background, 0, f.background.Length);

            for (int i = 0; (i = msg.IndexOf(ColorChar)) != -1; )
                msg = msg.Remove(i, 1);

            if (msg.Length > 0)
            {
                StringBuilder  s = new StringBuilder();
                string[]       m = msg.Split(new char[] {'\n' /*, '\r' */});
                ConsoleColor[] a = new ConsoleColor[(m.Length * 2) + 1];

                if (!bcwa)
                    l = m[0].Length + 2;

                for (int i = 0; i < m.Length; ++i)
                {
                    if (l < m[i].Length)
                        l = m[i].Length + 2;

                    m[i] = ' ' + m[i];
                }

                a[0] = fclr;
                s.Append(chrs[0]);
                
                for (int i = 0; i < l; ++i)
                    s.Append(chrs[1]);

                s.Append(chrs[2]);

                for (int i = 0, n = 1; i < m.Length; ++i)
                {
                    s.Append('\n');
                    s.Append(chrs[3]);
                    s.Append(ColorChar);
                    s.Append(m[i]);
                    
                    for (int j = m[i].Length; j < l; ++j)
                        s.Append(' ');

                    s.Append(ColorChar);
                    s.Append(chrs[3]);

                    a[n++] = tclr;
                    a[n++] = fclr;
                }

                s.Append('\n');
                s.Append(chrs[4]);

                for (int i = 0; i < l; ++i)
                    s.Append(chrs[5]);

                s.Append(chrs[6]);
                s.Append('\n');

                Messenger.Print(s.ToString(), a);
            }

            if ((Clean = b) && chrs != null)
                Array.Clear(chrs, 0, chrs.Length);
        }

        //-------------------------------------------------------------------------

        public static void Print
        (
              Frame        frm
            , string       msg
            , ConsoleColor fclr                                                     // Frame color.
            , ConsoleColor tclr                                                     // Text color.
            , bool         bcwa                                                     // Console width adjust.
        ){
            bool b = Clean;
            Clean  = true;

            if (frm == Frame.DOUBLE)
            {
                Messenger.Print
                (
                      new char[] { '╔', '═', '╗', '║', '╚', '═', '╝' }
                    , msg
                    , fclr
                    , tclr
                    , bcwa
                );
            }

            else if (frm == Frame.EXTRA)
            {
                Messenger.Print
                (
                      new char[] { '█', '▀', '█', '█', '█', '▄', '█' }
                    , msg
                    , fclr
                    , tclr
                    , bcwa
                );
            }

            else Messenger.Print
            (
                  new char[] { '┌', '─', '┐', '│', '└', '─', '┘' }
                , msg
                , fclr
                , tclr
                , bcwa
            );

            Clean = b;
        }

        //-------------------------------------------------------------------------

        public static void Print
        (
              Frame        frm
            , string       msg
            , ConsoleColor fclr                                                     // Frame and text color.
            , bool         bcwa                                                     // Console width adjust.
        ){
            Messenger.Print(frm, msg, fclr, fclr, bcwa);
        }

        //-------------------------------------------------------------------------

        public static void Print (Frame frm, string msg, ConsoleColor fclr)
        {
            Messenger.Print(frm, msg, fclr, true);
        }

        //-------------------------------------------------------------------------

        public static void Print
        (
              char         cfrm                                                     // Frame char.
            , string       msg
            , ConsoleColor fclr                                                     // Frame color.
            , ConsoleColor tclr                                                     // Text color.
            , bool         bcwa                                                     // Console width adjust.
        ){
            bool b = Clean;
            Clean  = true;

            Messenger.Print
            (
                  new char[] { cfrm, cfrm, cfrm, cfrm, cfrm, cfrm, cfrm }
                , msg
                , fclr
                , tclr
                , bcwa
            );

            Clean = b;
        }

        //-------------------------------------------------------------------------

        public static void Print (char cfrm, string msg, ConsoleColor fclr)
        {
            Messenger.Print(cfrm, msg, fclr, fclr, true);
        }
    }
}
