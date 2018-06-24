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
using System.Text.RegularExpressions;
using System.IO;
using System.Reflection;

namespace Jarol.IO
{
    public class Finder
    {
        public enum Usher
        {
              Files       = 1
            , Directories = 2
            , All         = 3
        };

        public enum Mode
        {
              Basic
            , Glob
            , ExtendedGlob
            , Regex
        };

        //----------------------------------------------------------------------------------

        private static class CharClasses
        {
            public const string alnum  = "a-zA-Z0-9";
            public const string alpha  = "a-zA-Z";
            public const string ascii  = "\x00-\x7F";
            public const string blank  = "\\s\t";
            public const string cntrl  = "\x00-\x1F\x7F";
            public const string digit  = "0-9";
            public const string graph  = "\x21-\x7E";
            public const string lower  = "a-z";
            public const string print  = "\x20-\x7E";
            public const string punct  = "!\"#$%&'()*+,\\-\\./:;<=>?@\\[\\\\]^_`{|}~";
            public const string space  = "\\s\t\r\n\v\f";
            public const string upper  = "A-Z";
            public const string xdigit = "0-9a-fA-F";
        };

        //----------------------------------------------------------------------------------

        private static class CharMap                                                          // ISO/IEC 8859-1, Latin 1 (Wester European).
        {
            public const string NUL                   = "\x00";
            public const string SOH                   = "\x01";
            public const string STX                   = "\x02";
            public const string ETX                   = "\x03";
            public const string EOT                   = "\x04";
            public const string ENQ                   = "\x05";
            public const string ACK                   = "\x06";
            public const string alert                 = "\x07";
            public const string BEL                   = "\x07";
            public const string backspace             = "\x08";
            public const string BS                    = "\x08";
            public const string tab                   = "\x09";
            public const string HT                    = "\x09";
            public const string newline               = "\x0A";
            public const string LF                    = "\x0A";
            public const string vertical_tab          = "\x0B";
            public const string VT                    = "\x0B";
            public const string form_feed             = "\x0C";
            public const string FF                    = "\x0C";
            public const string carriage_return       = "\x0D";
            public const string CR                    = "\x0D";
            public const string SO                    = "\x0E";
            public const string SI                    = "\x0F";
            public const string DLE                   = "\x10";
            public const string DC1                   = "\x11";
            public const string DC2                   = "\x12";
            public const string DC3                   = "\x13";
            public const string DC4                   = "\x14";
            public const string NAK                   = "\x15";
            public const string SYN                   = "\x16";
            public const string ETB                   = "\x17";
            public const string CAN                   = "\x18";
            public const string EM                    = "\x19";
            public const string SUB                   = "\x1A";
            public const string ESC                   = "\x1B";
            public const string FS                    = "\x1C";
            public const string IS4                   = "\x1C";
            public const string IS3                   = "\x1D";
            public const string GS                    = "\x1D";
            public const string intro                 = "\x1D";
            public const string IS2                   = "\x1E";
            public const string RS                    = "\x1E";
            public const string IS1                   = "\x1F";
            public const string US                    = "\x1F";
            public const string space                 = "\x20";
            public const string exclamation_mark      = "\x21";
            public const string quotation_mark        = "\x22";
            public const string number_sign           = "\x23";
            public const string dollar_sign           = "\x24";
            public const string percent_sign          = "\x25";
            public const string ampersand             = "\x26";
            public const string apostrophe            = "\x27";
            public const string left_parenthesis      = "\x28";
            public const string right_parenthesis     = "\x29";
            public const string asterisk              = "\x2A";
            public const string plus_sign             = "\x2B";
            public const string comma                 = "\x2C";
            public const string hyphen                = "\x2D";
            public const string hyphen_minus          = "\x2D";
            public const string period                = "\x2E";
            public const string full_stop             = "\x2E";
            public const string slash                 = "\x2F";
            public const string solidus               = "\x2F";
            public const string zero                  = "\x30";
            public const string one                   = "\x31";
            public const string two                   = "\x32";
            public const string three                 = "\x33";
            public const string four                  = "\x34";
            public const string five                  = "\x35";
            public const string six                   = "\x36";
            public const string seven                 = "\x37";
            public const string eight                 = "\x38";
            public const string nine                  = "\x39";
            public const string colon                 = "\x3A";
            public const string semicolon             = "\x3B";
            public const string less_than_sign        = "\x3C";
            public const string equals_sign           = "\x3D";
            public const string greater_than_sign     = "\x3E";
            public const string question_mark         = "\x3F";
            public const string commercial_at         = "\x40";
            public const string A                     = "\x41";
            public const string B                     = "\x42";
            public const string C                     = "\x43";
            public const string D                     = "\x44";
            public const string E                     = "\x45";
            public const string F                     = "\x46";
            public const string G                     = "\x47";
            public const string H                     = "\x48";
            public const string I                     = "\x49";
            public const string J                     = "\x4A";
            public const string K                     = "\x4B";
            public const string L                     = "\x4C";
            public const string M                     = "\x4D";
            public const string N                     = "\x4E";
            public const string O                     = "\x4F";
            public const string P                     = "\x50";
            public const string Q                     = "\x51";
            public const string R                     = "\x52";
            public const string S                     = "\x53";
            public const string T                     = "\x54";
            public const string U                     = "\x55";
            public const string V                     = "\x56";
            public const string W                     = "\x57";
            public const string X                     = "\x58";
            public const string Y                     = "\x59";
            public const string Z                     = "\x5A";
            public const string left_square_bracket   = "\x5B";
            public const string left_sq_br            = "\x5B";
            public const string backslash             = "\x5C";
            public const string reverse_solidus       = "\x5C";
            public const string right_square_bracket  = "\x5D";
            public const string right_sq_br           = "\x5D";
            public const string circumflex            = "\x5E";
            public const string circumflex_accent     = "\x5E";
            public const string underscore            = "\x5F";
            public const string low_line              = "\x5F";
            public const string grave_accent          = "\x60";
            public const string a                     = "\x61";
            public const string b                     = "\x62";
            public const string c                     = "\x63";
            public const string d                     = "\x64";
            public const string e                     = "\x65";
            public const string f                     = "\x66";
            public const string g                     = "\x67";
            public const string h                     = "\x68";
            public const string i                     = "\x69";
            public const string j                     = "\x6A";
            public const string k                     = "\x6B";
            public const string l                     = "\x6C";
            public const string m                     = "\x6D";
            public const string n                     = "\x6E";
            public const string o                     = "\x6F";
            public const string p                     = "\x70";
            public const string q                     = "\x71";
            public const string r                     = "\x72";
            public const string s                     = "\x73";
            public const string t                     = "\x74";
            public const string u                     = "\x75";
            public const string v                     = "\x76";
            public const string w                     = "\x77";
            public const string x                     = "\x78";
            public const string y                     = "\x79";
            public const string z                     = "\x7A";
            public const string left_brace            = "\x7B";
            public const string left_curly_bracket    = "\x7B";
            public const string vertical_line         = "\x7C";
            public const string right_brace           = "\x7D";
            public const string right_curly_bracket   = "\x7D";
            public const string tilde                 = "\x7E";
            public const string DEL                   = "\x7F";
            public const string delete                = "\x7F";
            public const string DT                    = "\x7F";
            public const string PAD                   = "\x80";
            public const string HOP                   = "\x81";
            public const string BPH                   = "\x82";
            public const string NBH                   = "\x83";
            public const string IND                   = "\x84";
            public const string NEL                   = "\x85";
            public const string SSA                   = "\x86";
            public const string ESA                   = "\x87";
            public const string HTS                   = "\x88";
            public const string HTJ                   = "\x89";
            public const string VTS                   = "\x8A";
            public const string PLD                   = "\x8B";
            public const string PLU                   = "\x8C";
            public const string RI                    = "\x8D";
            public const string SS2                   = "\x8E";
            public const string SS3                   = "\x8F";
            public const string DCS                   = "\x90";
            public const string PU1                   = "\x91";
            public const string PU2                   = "\x92";
            public const string STS                   = "\x93";
            public const string CCH                   = "\x94";
            public const string MW                    = "\x95";
            public const string SPA                   = "\x96";
            public const string EPA                   = "\x97";
            public const string SOS                   = "\x98";
            public const string SGCI                  = "\x99";
            public const string SCI                   = "\x9A";
            public const string CSI                   = "\x9B";
            public const string ST                    = "\x9C";
            public const string OSC                   = "\x9D";
            public const string PM                    = "\x9E";
            public const string APC                   = "\x9F";
            public const string no_break_space        = "\xA0";
            public const string inverted_exclamation  = "\xA1";
            public const string cent_sign             = "\xA2";
            public const string pound_sign            = "\xA3";
            public const string currency_sign         = "\xA4";
            public const string yen_sign              = "\xA5";
            public const string broken_bar            = "\xA6";
            public const string section_sign          = "\xA7";
            public const string umlaut                = "\xA8";
            public const string copyright_sign        = "\xA9";
            public const string feminine_ordinal_a    = "\xAA";
            public const string left_angle_quotation  = "\xAB";
            public const string not_sign              = "\xAC";
            public const string soft_hyphen           = "\xAD";
            public const string registered_mark       = "\xAE";
            public const string macron                = "\xAF";
            public const string degree_sign           = "\xB0";
            public const string plus_minus_sign       = "\xB1";
            public const string superscript_2         = "\xB2";
            public const string superscript_3         = "\xB3";
            public const string acute_accent          = "\xB4";
            public const string micro_sign            = "\xB5";
            public const string pilcrow_sign          = "\xB6";
            public const string middle_dot            = "\xB7";
            public const string cedilla               = "\xB8";
            public const string superscript_1         = "\xB9";
            public const string masculine_ordinal_o   = "\xBA";
            public const string right_angle_quotation = "\xBB";
            public const string one_quarter           = "\xBC";
            public const string one_half              = "\xBD";
            public const string three_quarters        = "\xBE";
            public const string inverted_question     = "\xBF";
            public const string A_grave               = "\xC0";
            public const string A_acute               = "\xC1";
            public const string A_circumflex          = "\xC2";
            public const string A_tilde               = "\xC3";
            public const string A_umlaut              = "\xC4";
            public const string A_ring                = "\xC5";
            public const string AE                    = "\xC6";
            public const string C_cedilla             = "\xC7";
            public const string E_grave               = "\xC8";
            public const string E_acute               = "\xC9";
            public const string E_circumflex          = "\xCA";
            public const string E_umlaut              = "\xCB";
            public const string I_grave               = "\xCC";
            public const string I_acute               = "\xCD";
            public const string I_circumflex          = "\xCE";
            public const string I_umlaut              = "\xCF";
            public const string ETH                   = "\xD0";
            public const string N_tilde               = "\xD1";
            public const string O_grave               = "\xD2";
            public const string O_acute               = "\xD3";
            public const string O_circumflex          = "\xD4";
            public const string O_tilde               = "\xD5";
            public const string O_umlaut              = "\xD6";
            public const string multiplication_sign   = "\xD7";
            public const string O_slash               = "\xD8";
            public const string U_grave               = "\xD9";
            public const string U_acute               = "\xDA";
            public const string U_circumflex          = "\xDB";
            public const string U_umlaut              = "\xDC";
            public const string Y_acute               = "\xDD";
            public const string THORN                 = "\xDE";
            public const string sharp_s               = "\xDF";
            public const string a_grave               = "\xE0";
            public const string a_acute               = "\xE1";
            public const string a_circumflex          = "\xE2";
            public const string a_tilde               = "\xE3";
            public const string a_umlaut              = "\xE4";
            public const string a_ring                = "\xE5";
            public const string ae                    = "\xE6";
            public const string c_cedilla             = "\xE7";
            public const string e_grave               = "\xE8";
            public const string e_acute               = "\xE9";
            public const string e_circumflex          = "\xEA";
            public const string e_umlaut              = "\xEB";
            public const string i_grave               = "\xEC";
            public const string i_acute               = "\xED";
            public const string i_circumflex          = "\xEE";
            public const string i_umlaut              = "\xEF";
            public const string eth                   = "\xF0";
            public const string n_tilde               = "\xF1";
            public const string o_grave               = "\xF2";
            public const string o_acute               = "\xF3";
            public const string o_circumflex          = "\xF4";
            public const string o_tilde               = "\xF5";
            public const string o_umlaut              = "\xF6";
            public const string division_sign         = "\xF7";
            public const string o_slash               = "\xF8";
            public const string u_grave               = "\xF9";
            public const string u_acute               = "\xFA";
            public const string u_circumflex          = "\xFB";
            public const string u_umlaut              = "\xFC";
            public const string y_acute               = "\xFD";
            public const string thorn                 = "\xFE";
            public const string y_umlaut              = "\xFF";
        };

        //----------------------------------------------------------------------------------

        private static class CharEquivalences
        {
            public const string a = "aàáâãäå";
            public const string A = "AÀÁÂÃÄÅ";
            public const string b = "b";
            public const string B = "B";
            public const string c = "cç";
            public const string C = "CÇ";
            public const string d = "d";
            public const string D = "D";
            public const string e = "eèéêë";
            public const string E = "EÈÉÊË";
            public const string f = "f";
            public const string F = "F";
            public const string g = "g";
            public const string G = "G";
            public const string h = "h";
            public const string H = "H";
            public const string i = "iìíîï";
            public const string I = "IÌÍÎÏ";
            public const string j = "j";
            public const string J = "J";
            public const string k = "k";
            public const string K = "K";
            public const string l = "l";
            public const string L = "L";
            public const string m = "m";
            public const string M = "M";
            public const string n = "nñ";
            public const string N = "NÑ";
            public const string o = "oòóôõö";
            public const string O = "OÒÓÔÕÖ";
            public const string p = "p";
            public const string P = "P";
            public const string q = "q";
            public const string Q = "Q";
            public const string r = "r";
            public const string R = "R";
            public const string s = "s";
            public const string S = "S";
            public const string t = "t";
            public const string T = "T";
            public const string u = "uùúûü";
            public const string U = "UÙÚÛÜ";
            public const string v = "v";
            public const string V = "V";
            public const string w = "w";
            public const string W = "W";
            public const string x = "x";
            public const string X = "X";
            public const string y = "yýÿ";
            public const string Y = "YÝŸ";
            public const string z = "z";
            public const string Z = "Z";
        };

        //----------------------------------------------------------------------------------

        private static readonly Type         _classes_t     = typeof(CharClasses);
        private static readonly MemberInfo[] _classes       = _classes_t.GetMembers();
        private static readonly Type         _charmap_t     = typeof(CharMap);
        private static readonly MemberInfo[] _charmap       = _charmap_t.GetMembers();
        private static readonly Type         _eqivalences_t = typeof(CharEquivalences);
        private static readonly MemberInfo[] _eqivalences   = _eqivalences_t.GetMembers();

        //----------------------------------------------------------------------------------

        private const string _currentdir          = ".";
        private const string _parentdir           = _currentdir + _currentdir;
        private const string _index               = "index";
        private const string _count               = "count";
        private const string _index_e_msg         = "The index argument is less than 0!";
        private const string _count_e_msg         = "The count argument is greater than the allowable length!";
        private const string _invalid_value_e_msg = "The {0} field can not be equal to the following value: {1}";
        private const string _invalid_chars_e_msg = "The {0} field can not contain the standard escape characters!";
        private const string _invalid_unc_e_msg   = "The UNC path must have the following format {0}{0}server{0}share!";
        private const string _empty_field_e_msg   = "The {0} field can not be empty!";
        private const string _same_val_e_msg      = "The Escape and Separator fields can not contain the same value!";
        private const string _separator_name      = "Separator";
        private const string _escape_name         = "Escape";
        private const string _regex_escape_chars  = "AbBdDGkpPsSwWzZ";
        private const string _escape_chars        = "\a\b\t\n\v\f\r";
        
        //----------------------------------------------------------------------------------

        private static readonly string _separator = Path.DirectorySeparatorChar.ToString();
        private static readonly string _escape    = "\\";
        private static readonly bool   _iswin     = _separator == _escape;
        private static readonly string _def_esc   = _iswin ? "/" : _escape;

        
        //----------------------------------------------------------------------------------

        protected Mode _mode;
        private string _sep_val          = _separator;
        private string _esc_val          = _def_esc;
        public bool    RaiseEmptyField   = true;
        public bool    RaiseAccessDenied = true;

        //----------------------------------------------------------------------------------

        public string Separator
        {
            get { return _sep_val; }
            set 
            {
                if (value == null)
                    _sep_val = _separator;

                else if (value.Trim() != string.Empty)
                {
                    foreach (char c in _escape_chars)
                        if (value.IndexOf(c) != -1)
                            throw new Exception(string.Format(_invalid_chars_e_msg, _separator_name));

                    _sep_val = value;
                }

                else if (RaiseEmptyField)
                    throw new Exception(string.Format(_empty_field_e_msg, _separator_name));

                if (_esc_val.Contains(_sep_val) || _sep_val.Contains(_esc_val))
                    throw new Exception(_same_val_e_msg);
            }
        }

        //----------------------------------------------------------------------------------

        public string Escape
        {
            get { return _esc_val; }
            set
            {
                if (value == null)
                    _esc_val = _def_esc;

                else if (value.Trim() != string.Empty)
                {
                    foreach (char c in _escape_chars)
                        if (value.IndexOf(c) != -1)
                            throw new Exception(string.Format(_invalid_chars_e_msg, _escape_name));

                    _esc_val = value;
                }

                else if (RaiseEmptyField)
                    throw new Exception(string.Format(_empty_field_e_msg, _escape_name));

                if (_esc_val.Contains(_sep_val) || _sep_val.Contains(_esc_val))
                    throw new Exception(_same_val_e_msg);
            }
        }

        //----------------------------------------------------------------------------------

        public Finder (Mode mode, string escape, string separator)
        {
            _mode     = mode;
            Escape    = escape;
            Separator = separator;
        }

        public Finder (Mode mode, string escape) : this(mode, escape, null) { }
        public Finder (Mode mode) : this(mode, null) { }

        //----------------------------------------------------------------------------------

        private bool AssertDirectories (string path, int length)
        {
            --length;

            int d = Separator.Length;
            int l = path.Length - d;

            for (int i = 0, n = i; (i = path.IndexOf(Separator, i)) != -1; n = i += d)
                if ((n < i || i == 0) && i < l) --length;

            return length == 0;
        }

        //----------------------------------------------------------------------------------

        private string[] SplitPath (string path)
        {
            List<string> l = new List<string>();
            int          x = 0;
            int          n = 0;
            int          d = Separator.Length - 1;
            int          c = path.Length - 1 - d;

            for (int i = 0; (i = path.IndexOf(Separator, i)) != -1; x = i, n = ++i + d)
            {
                if (i == 0)
                {
                    l.Add(Separator);

                    if (_iswin && path.IndexOf(Separator, i + 1) == i + d + 1)
                    {
                        l[0] += Separator;
                        i    += d;
                    }
                }

                else if (n < i && i < c)
                {
                    l.Add(path.Substring(n, i - n));

                    if (_iswin && l.Count == 1 && l[0].Length == 2 && l[0][1] == ':')
                        l[0] += Separator;
                }
            }

            if (l.Count == 0 && x == 0)
                --x;

            else x += d;

            if (n - ++d < c)
                c += d;

            if (!string.IsNullOrEmpty(path = path.Substring(++x, c - x)))
                l.Add(path);

            string[] r = l.ToArray();
            l.Clear();

            return r;
        }

        //----------------------------------------------------------------------------------
        
        private string JoinPath (string[] splitted, int index, int count)
        {
            string s = string.Empty;
            int    d = Separator.Length - 1;

            if (splitted != null && splitted.Length > 0)
            {
                if (index < 0)
                    throw new ArgumentException(_index_e_msg, _index);

                if ((count += index) > splitted.Length)
                    throw new ArgumentException(_count_e_msg, _count);

                for (int n = count - 1; index < count; ++index)
                {
                    string c = splitted[index];

                    if (!string.IsNullOrEmpty(c))
                    {
                        s += c;

                        if (index < n && c.LastIndexOf(Separator) != c.Length - 1 - d)
                            s += Separator;
                    }
                }
            }

            return s;
        }

        //----------------------------------------------------------------------------------

        private static bool HasEscape (string src, int index)
        {
            if (string.IsNullOrEmpty(src))
                return false;

            int n = _escape.Length;
            int l = src.Length;
            int c = 0;

            if ((index -= n) < 0 || index >= l)
                return false;

            for (; index > -1 && src.IndexOf(_escape, index) == index; index -= n)
                ++c;
            
            return c % 2 != 0;
        }

        //----------------------------------------------------------------------------------

        private static bool HasEscape (StringBuilder src, int index)
        {
            if (src == null)
                return false;

            int  n = _escape.Length;
            int  l = src.Length;
            int  r = -1;
            bool b = false;

            do
            {
                ++r;
                if ((index -= n) < 0 || index >= l)
                    break;

                int i = index;
                foreach (char c in _escape)
                    if (!(b = src[i++] == c))
                        break;
            }
            while (b);

            return r % 2 != 0;
        }

        //----------------------------------------------------------------------------------

        private static bool Locate 
        (
              MemberInfo[]  members
            , Type          type
            , StringBuilder factory
            , char          symbol
            , string        pattern
            , ref int       index
       ){
           string a = "[" + symbol;
           string b = symbol + "]";

           foreach (MemberInfo m in members)
           {
               if (m.MemberType == MemberTypes.Field)
               {
                   if (pattern.IndexOf(a + m.Name.Replace('_', '-') + b, index) == index)
                   {
                       factory.Append(((FieldInfo)m).GetValue(type));
                       index += m.Name.Length + 3;
                       return true;
                   }
               }
           }

           return false;
        }

        //----------------------------------------------------------------------------------

        private static bool Contains (string src, int index, char target)
        {
            for (int l = src.Length; index < l && (index = src.IndexOf(target, index)) != -1; ++index)
                if (!HasEscape(src, index)) return true;

            return false;
        }

        //----------------------------------------------------------------------------------

        private static string GlobToRegex (string pattern, bool extended)                          // The rules are as follows (POSIX.2, 3.13).
        {
            if (string.IsNullOrEmpty(pattern))
                return string.Empty;

            List<string>  r = new List<string>();
            StringBuilder s = new StringBuilder();
            int           a = 0;
            int           o = 0;
            bool          b, e;
            
            for (int c, d, i = 0, l = pattern.Length, m, n = l - 1; i < l; ++i)
            {
                switch (pattern[i])
                {
                    case '[':
                        b = false;
                        e = HasEscape(pattern, i);

                        if (!e && a > 0 && i < n)
                        {
                            switch (pattern[i + 1])
                            {
                                case ':':
                                    b = Locate
                                    (
                                          _classes
                                        , _classes_t
                                        , s
                                        , ':' 
                                        , pattern
                                        , ref i
                                    );
                                    break;

                                case '.':
                                    b = Locate
                                    (
                                          _charmap
                                        , _charmap_t
                                        , s
                                        , '.'
                                        , pattern
                                        , ref i
                                    );
                                    break;

                                case '=':
                                    b = Locate
                                    (
                                          _eqivalences
                                        , _eqivalences_t
                                        , s
                                        , '='
                                        , pattern
                                        , ref i
                                    );
                                    break;
                            }
                        }

                        if (b) break;

                        if (++a > 1 || pattern.IndexOf(']', i + 1) == -1)
                        {
                            if (!e)
                                s.Append(_escape);

                            --a;
                        }

                        else if (e)
                            --a;

                        s.Append('[');
                        break;

                    case ']':
                        if (i == 0 || (a == 0 && !HasEscape(pattern, i)))
                            s.Append(_escape);

                        else if (a > 0)
                        {
                            c = 0;
                            d = 0;
                            m = s.Length - 1;

                            if (i < n && s[m] == '[' && !HasEscape(s, m) && Contains(pattern, i + 1, ']'))
                                ++d;

                            else for (int j = i + 1; j < l; ++j)
                            {
                                if (pattern[j] == '[' && !HasEscape(pattern, j))
                                    ++c;

                                else if (pattern[j] == ']' && !HasEscape(pattern, j))
                                    ++d;
                            }

                            if (d == 0 || c == d || c > d)
                                --a;

                            else s.Append(_escape);
                        }

                        s.Append(']');
                        break;

                    case '!':
                        if (a > 0 && s[m = s.Length - 1] == '[' && !HasEscape(s, m))
                            s.Append('^');

                        else if (!extended || (c = i + 1) >= l || pattern[c] != '(')
                            s.Append('!');

                        else
                        {
                            s.Append("(?!");
                            r.Add(")");
                            ++i;
                        }

                        break;

                    case '*':
                        if (a > 0 || HasEscape(pattern, i))
                            s.Append('*');

                        else if (!extended || (c = i + 1) >= l || pattern[c] != '(')
                            s.Append(".*");

                        else
                        {
                            s.Append('(');
                            r.Add(")*");
                            ++i;
                        }

                        break;

                    case '?':
                        if (a > 0 || HasEscape(pattern, i))
                            s.Append('?');

                        else if (!extended || (c = i + 1) >= l || pattern[c] != '(')
                            s.Append('.');

                        else
                        {
                            s.Append('(');
                            r.Add(")?");
                            ++i;
                        }

                        break;

                    case '+':
                        if (a > 0 || HasEscape(pattern, i))
                            s.Append('+');

                        else if (!extended || (c = i + 1) >= l || pattern[c] != '(')
                            s.Append("\\+");

                        else
                        {
                            s.Append('(');
                            r.Add(")+");
                            ++i;
                        }

                        break;

                    case '@':
                        if (!extended || a > 0 || HasEscape(pattern, i) || (c = i + 1) >= l || pattern[c] != '(')
                            s.Append('@');

                        else
                        {
                            s.Append('(');
                            r.Add(")");
                            ++i;
                        }

                        break;

                    case '.':
                        s.Append(HasEscape(pattern, i) ? "." : "\\.");
                        break;

                    case '{':
                        if (a > 0 || HasEscape(pattern, i))
                            s.Append('{');

                        else
                        {
                            ++o;
                            s.Append('(');
                        }

                        break;

                    case '}':
                        if (a > 0 || HasEscape(pattern, i))
                            s.Append('}');

                        else if (o > 0)
                        {
                            --o;
                            s.Append(')');
                        }

                        else s.Append("\\}");
                        break;

                    case ',':
                        s.Append(o > 0 && !HasEscape(pattern, i) ? '|' : ',');
                        break;

                    case '(':
                        s.Append(a > 0 || HasEscape(pattern, i) ? "(" : "\\(");
                        break;

                    case ')':
                        if (HasEscape(pattern, i) || a > 0)
                            s.Append(')');

                        else if (!extended || (c = r.Count) < 1)
                            s.Append("\\)");

                        else
                        {
                            s.Append(r[--c]);
                            r.RemoveAt(c);
                        }
                        break;

                    case '|':
                        s.Append(a > 0 || HasEscape(pattern, i) || (/*extended &&*/ r.Count > 0 && a < 1) ? "|" : "\\|");
                        break;

                    case '$':
                        s.Append(a > 0 || HasEscape(pattern, i) ? "$" : "\\$");
                        break;

                    case '^':
                        s.Append(i == 0 ? "\\^" : "^");
                        break;

                    default:
                        if (HasEscape(pattern, i)) foreach (char f in _regex_escape_chars)
                        {
                            if (f == pattern[i])
                            {
                                s.Remove(i - 1, 1);
                                break;
                            }
                        }

                        s.Append(pattern[i]);
                        break;
                }
            }

            if (a != 0 || o != 0 || r.Count > 0)
                throw new Exception("There are bad expressions laid in the pattern: \"" + pattern + '"');

            pattern = s.ToString();
            s.Remove(0, s.Length);

            return pattern;
        }

        //----------------------------------------------------------------------------------

        private static void Dispatcher (List<string> list, string[] items)
        {
            list.AddRange(items);
            Array.Clear(items, 0, items.Length);
        }

        //----------------------------------------------------------------------------------

        private string ReplaceEscapes (string pattern)
        {
            if (Escape == _escape || !pattern.Contains(Escape))
                return pattern;

            StringBuilder s = new StringBuilder();

            for (int i = 0, l = pattern.Length, x = Escape.Length; i < l; ++i)
            {
                bool b = false;
                int  n = i;
                int  c = -1;

                do
                {
                    ++c;
                    b = pattern.IndexOf(Escape, n, x) == n;

                    if (c > 1)
                    {
                        s.Append(Escape);
                        i = n - 1;
                        break;
                    }

                    n += Escape.Length;
                }
                while (b);

                if (c == 0)
                    s.Append(pattern[i]);

                else if (c == 1)
                {
                    s.Append(_escape);
                    i += Escape.Length - 1;
                }
            }

            pattern = s.ToString();
            s.Remove(0, s.Length);

            return pattern;
        }

        //----------------------------------------------------------------------------------

        private string[] Forwarder
        (
              string[] paths
            , string   pattern
            , bool     ignorecase
            , bool     reverse
        ){
            List<string> l = new List<string>();
            int          n;

            pattern = ReplaceEscapes(pattern);

            if (_mode == Mode.Basic)
            {
                foreach (char c in _regex_escape_chars)
                    pattern = pattern.Replace(_escape + c, string.Empty);

                pattern = Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".");
            }

            else if (_mode == Mode.ExtendedGlob)
                pattern = GlobToRegex(pattern, true);

            else if (_mode == Mode.Glob)
                pattern = GlobToRegex(pattern, false);

            else
            {
                /*
                if (pattern[0] == '^')
                    pattern = _escape + pattern;
                */

                n = pattern.Length - 1;

                if (n > -1 && pattern[n] == '$' && !HasEscape(pattern, n))
                    pattern = pattern.Insert(n, _escape);
            }

            if (!string.IsNullOrEmpty(pattern))
            {
                RegexOptions o = RegexOptions.Singleline | RegexOptions.Compiled;

                if (ignorecase)
                    o |= RegexOptions.IgnoreCase;

                Regex r = new Regex('^' + pattern + '$', o);

                foreach (string s in paths)
                {
                    if (r.IsMatch(s.Substring(s.LastIndexOf(_separator) + 1)))
                    {
                        if (!reverse)
                            l.Add(s);
                    }

                    else if (reverse)
                        l.Add(s);
                }
            }

            Array.Clear(paths, 0, paths.Length);
            paths = l.ToArray();
            l.Clear();

            return paths;
        }

        //----------------------------------------------------------------------------------

        private string[] GetPaths
        (
              string pattern
            , Usher  usher
            , bool   ignorecase
            , bool   reverse
            , bool   recursively
            , int    index
        ){
            if (index == 0 && (pattern == null || (pattern = pattern.Trim()).Length < 1))
                return new string[0];

            if (pattern.EndsWith(Separator))
                pattern += _mode == Mode.Regex ? ".*" : "*";

            string p;
            Regex  r = null;
            Match  m = null;

            if (index == 0)
            {
                p = @"(\*|\?";

                if (_mode != Mode.Basic)
                {
                    p += @"|\[|\]|\{|\}";

                    if (_mode != Mode.Glob)
                    {
                        p += @"|\||\)";

                        if (_mode == Mode.ExtendedGlob)
                            p += @"|[?@+*!]\(";

                        else
                        {
                            p += @"|\(|#|-|\.|\+|\(\?\(|\(\?(<?[=!]?|[>:=!#imnsx]-?[imnsx]?)" +
                                 @"|[*+?}]\?|\$[{\$&`'+_]|\)[+*?]|\{\d+,?\d*\}?";

                            foreach (char c in _regex_escape_chars)
                                p += @"|\\" + c;
                        }
                    }
                }

                p += ')';
                r = new Regex('^' + p + '$', RegexOptions.Singleline);

                if ((m = r.Match(Escape)).Success)
                    throw new Exception(string.Format(_invalid_value_e_msg, _escape_name, '"' +  m.Value + '"'));

                if ((m = r.Match(Separator)).Success)
                    throw new Exception(string.Format(_invalid_value_e_msg, _separator_name, '"' + m.Value + '"'));

                r = new Regex(p, RegexOptions.Singleline);
            }

            List<string> l = new List<string>();
            string       u = Separator + Separator;
            string[]     s = SplitPath(pattern);
            int          n = s.Length - 1;
            string       f = s[n];
            int          i = 0;

            Array.Clear(s, n, 1);
            Array.Resize<string>(ref s, n);

            if (n == 0)
            {
                s = new string[1] { _currentdir };
                ++n;
            }

            else if (r != null && r.IsMatch(s[0]))
            {
                l.Add(_currentdir);
                Dispatcher(l, s);
                s = l.ToArray();
                l.Clear();
                ++n;
            }

            if (index == 0)
                ++index;

            try
            {
                for (p = JoinPath(s, 0, index); index < n; ++index)
                {
                    if (_iswin && index == 1 && s[0] == u)
                    {
                        if (2 >= n || s[1] == _currentdir || s[1] == _parentdir || s[2] == _currentdir || s[2] == _parentdir)
                            throw new Exception(string.Format(_invalid_unc_e_msg, Separator));

                        if (r != null && (r.IsMatch(s[1]) || r.IsMatch(s[2])))
                            throw new Exception(string.Format(_invalid_unc_e_msg, Separator));

                        p += s[1] + Separator + s[index = 2];
                        continue;
                    }

                    else if (s[index] == _currentdir || s[index] == _parentdir)
                    {
                        p += Separator + s[index];
                        continue;
                    }

                    string[] d = Forwarder
                    (
                          Directory.GetDirectories(p.Replace(Separator, _separator))
                        , s[index]
                        , ignorecase
                        , false
                    );

                    if ((i = d.Length) == 0)
                        break;

                    else if (i < 2)
                        p = d[0];

                    else
                    {
                        i = index + 1;
                        foreach (string c in d)
                        {
                            if (!string.IsNullOrEmpty(pattern = JoinPath(s, i, n - i)))
                                pattern += Separator;

                            pattern = c.Replace(_separator, Separator) + Separator + pattern;

                            if (!AssertDirectories(pattern, n))
                                break;

                            Dispatcher
                            (
                                  l
                                , GetPaths(pattern + f, usher, ignorecase, reverse, recursively, i)
                            );
                        }
                    }

                    Array.Clear(d, 0, d.Length);
                }

                if (AssertDirectories(p, n))
                {
                    Array.Clear(s, 0, n);

                    p = p.Replace(Separator, _separator);
                    s = Directory.GetDirectories(p);
                    n = s.Length;

                    if (recursively) foreach (string c in s) Dispatcher
                    (
                          l
                        , GetPaths
                          (
                                c.Replace(_separator, Separator) + Separator + f
                              , usher
                              , ignorecase
                              , reverse
                              , recursively
                              , 0
                         )
                    );

                    if ((usher & Usher.Directories) != 0)
                        Dispatcher(l, Forwarder(s, f, ignorecase, reverse));

                    if ((usher & Usher.Files) != 0) 
                        Dispatcher(l, Forwarder(Directory.GetFiles(p), f, ignorecase, reverse));
                }
            }

            catch (UnauthorizedAccessException e)
            { 
                if (RaiseAccessDenied)
                    throw e;
            }

            Array.Clear(s, 0, n);
            s = l.ToArray();
            l.Clear();

            Array.Sort<string>(s);
            return s;
        }

        //----------------------------------------------------------------------------------

        public string[] GetCustom
        (
              string pattern
            , Usher  usher
            , bool   ignorecase  = false
            , bool   reverse     = false
            , bool   recursively = false
        ){
            return GetPaths(pattern, usher, ignorecase, reverse, recursively, 0);
        }

        //----------------------------------------------------------------------------------

        public string[] GetFiles
        (
              string pattern
            , bool   ignorecase  = false
            , bool   reverse     = false
            , bool   recursively = false
        ){
            return GetCustom(pattern, Usher.Files, ignorecase, reverse, recursively);
        }

        //----------------------------------------------------------------------------------

        public string[] GetDirectories
        (
              string pattern
            , bool   ignorecase  = false
            , bool   reverse     = false
            , bool   recursively = false
        ){
            return GetCustom(pattern, Usher.Directories, ignorecase, reverse, recursively);
        }

        //----------------------------------------------------------------------------------

        public static string[] GetCustom
        (
              string pattern
            , Mode   mode
            , Usher  usher
            , bool   ignorecase  = false
            , bool   recursively = false
            , bool   reverse     = false
            , string escape      = null
            , string separator   = null
        ){
            return new Finder(mode, escape, separator).GetCustom
            (
                  pattern
                , usher
                , ignorecase
                , reverse
                , recursively
            );
        }

        //----------------------------------------------------------------------------------

        public static string[] GetFiles
        (
              string pattern
            , Mode   mode
            , bool   ignorecase  = false
            , bool   recursively = false
            , bool   reverse     = false
            , string escape      = null
            , string separator   = null
        ){
            return new Finder(mode, escape, separator).GetFiles
            (
                  pattern
                , ignorecase
                , reverse
                , recursively
            );
        }

        //----------------------------------------------------------------------------------

        public static string[] GetDirectories
        (
              string pattern
            , Mode   mode
            , bool   ignorecase  = false
            , bool   recursively = false
            , bool   reverse     = false
            , string escape      = null
            , string separator   = null
        ){
            return new Finder(mode, escape, separator).GetDirectories
            (
                  pattern
                , ignorecase
                , reverse
                , recursively
            );
        }
    }
}
