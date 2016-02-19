/* Copyright © 2015 Jon Allen <ylixir@gmail>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What You Want To Public License,
 * as published by Sam Hocevar. See the COPYING file for more details.
 */

/* Some useful references:
 * 
 * a working javascript totp useful to debug
 * http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript/
 *
 * the documents with the relevant specifications
 * http://tools.ietf.org/html/rfc6238
 * https://tools.ietf.org/html/rfc4226
 * https://tools.ietf.org/html/rfc4648
 */

using System;
using System.Security.Cryptography;
using System.Text;
using System.Globalization;
using System.Collections.Generic;

namespace yotp {
  class MainClass {
    /// <summary>
    /// Time zero. The unix epoch.
    /// </summary>
    protected static readonly long T0 = 0;
    protected static readonly DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    /// <summary>
    /// The timestep, with variable name chosen by rfc 6238.
    /// </summary>
    protected static readonly long X = 30;

    /// <summary>
    /// Unix time for the specified t.
    /// </summary>
    /// <param name="t">Time. Perhaps epoch or DateTime.UtcNow.</param>
    protected static long unixtime (DateTime t) {
      return (long)(t - epoch).TotalSeconds;
    }
    /// <summary>
    /// Get current unixtime.
    /// </summary>
    protected static long now() {
      return unixtime (DateTime.UtcNow);
    }
    /// <summary>
    /// Get the byte array of the specified counter, high order first.
    /// </summary>
    /// <param name="counter">Counter.</param>
    protected static byte[] countbytes(long count_int) {
      byte[] result = new byte[8];
      for(int i=0;i<8;i++)
        result[7-i]=(byte)(count_int>>(i*8));
      return result;
    }
    /// <summary>
    /// Truncate the hash as specified in RFC 4226.
    /// </summary>
    /// <param name="hash">Hash.</param>
    protected static int Truncate(byte[] hash) {
      int result = 0;
      int offset = hash [19] & 0x0f;
      for (int i = 0; i < 4; i++) {
        result |= ((int)(hash [3 - i + offset])) << (i*8);
      }
      return result;
    }
    /// <summary>
    /// Convert the secret from a hex string to a byte sequence.
    /// </summary>
    /// <param name="secret">Secret.</param>
    protected static byte[] hex_key(string secret) {
      byte[] result = new byte[secret.Length/2];
      for (int i = 0; i < secret.Length; i += 2) {
        result[i/2]=(byte)Int16.Parse(secret.Substring (i,2),NumberStyles.AllowHexSpecifier);
      }
      return result;
    }

    /// <summary>
    /// Convert the secret from a base32 string to a byte sequence.
    /// </summary>
    /// <param name="secret">Secret.</param>
    protected static byte[] base32_key(string secret) {
      int buffer=0;
      byte[] result = new byte[10];
      //the dictionary should throw an exception whenever we hit anything not in it
      //this is ideal for now, but as the program grows this may require a subtler touch
      Dictionary<char,int> value_lookup = new Dictionary<char, int> () {
        {'A', 0},{'B', 1},{'C', 2},{'D', 3},{'E', 4},{'F', 5},{'G', 6},{'H', 7},
        {'I', 8},{'J', 9},{'K',10},{'L',11},{'M',12},{'N',13},{'O',14},{'P',15},
        {'Q',16},{'R',17},{'S',18},{'T',19},{'U',20},{'V',21},{'W',22},{'X',23},
        {'Y',24},{'Z',25},{'2',26},{'3',27},{'4',28},{'5',29},{'6',30},{'7',31},
        {'0',14},{'1', 8},{'l',8}
      };
      buffer = value_lookup[secret[0]];
      for (int i = 1; i < 80; i++) {
        if (0 == i % 5) {
          buffer <<= 5;
          buffer |= value_lookup[secret[i/5]];
        }
        if (0 == i % 8) {
          //(i/5+1)*5-i) is the number of low order bits that we can't use yet
          result [i / 8 - 1] = (byte)(buffer>>(i/5+1)*5-i);
          buffer &= -1 ^ (0xFF << (i/5+1)*5-i); //discard the bits we just used
        }
      };
      result [9] = (byte)buffer;
      return result;
    }

    /// <summary>
    /// Do the HMAC algorithm as referenced in RFC 4226.
    /// </summary>
    /// <returns>The SHA1 hash.</returns>
    /// <param name="K">Secret key.</param>
    /// <param name="C">Count.</param>
    protected static byte[] HMAC_SHA_1(byte[] K, byte[] C) {
      HMACSHA1 hmac = new HMACSHA1(K);
      return hmac.ComputeHash (C);
    }

    public static int Main (string[] args) {
      if (0==args.Length) {
				Console.WriteLine ("usage: yotp secret1 secret2 ...");
				return 1;
			}
      foreach (string secret in args) {
        byte[] K;
        if(20 == secret.Length)
          K = hex_key (secret);
        else if(16 == secret.Length)
          K = base32_key(secret);
        else
        {
          Console.WriteLine ("I don't know what to do with this secret");
          break;
        }

        byte[] C = countbytes ((now () - T0) / X);
        int hotp = Truncate (HMAC_SHA_1(K,C)) & 0x7fffffff;
        Console.WriteLine ((hotp % (int)Math.Pow (10, 6)).ToString ("D6"));
			}
      return 0;
		}
	}
}
