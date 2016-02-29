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
  class HOTP {
    /// <summary>
    /// The thing that does the HMAC algorithm as referenced in RFC 4226.
    /// </summary>
    /// <returns>The SHA1 hash.</returns>
    protected HMAC HMACHasher;
    /// <summary>
    /// This is the secret that is hashed and salted to generate the one time password.
    /// </summary>
    protected virtual byte[] K{
      get { return HMACHasher.Key; }
      set { HMACHasher.Key = value; }
    }
    /// <summary>
    /// This is the counter that is used to salt the hash when generating the password.
    /// </summary>
    protected virtual byte[] C;

    protected byte[] Hash{
      get{
        return HMACHasher.ComputeHash (C);
      }
    }

    public HOTP(){
      HMACHasher = new HMACSHA1 ();
      C = {0};
    }
    /// <summary>
    /// Convert the key to and from a base32 string.
    /// </summary>
    public string base32_secret{
      set{
        int buffer=0;
        byte[] secret = new byte[value.Length*5/8];//5 bits per base 32 digit, 8 bits per byte
        //the dictionary should throw an exception whenever we hit anything not in it
        //this is ideal for now, but as the program grows this may require a subtler touch
        Dictionary<char,int> value_lookup = new Dictionary<char, int> () {
          {'A', 0},{'B', 1},{'C', 2},{'D', 3},{'E', 4},{'F', 5},{'G', 6},{'H', 7},
          {'I', 8},{'J', 9},{'K',10},{'L',11},{'M',12},{'N',13},{'O',14},{'P',15},
          {'Q',16},{'R',17},{'S',18},{'T',19},{'U',20},{'V',21},{'W',22},{'X',23},
          {'Y',24},{'Z',25},{'2',26},{'3',27},{'4',28},{'5',29},{'6',30},{'7',31},
          {'0',14},{'1', 8},{'l',8}
        };
        buffer = value_lookup[value[0]]; //get the bits for the first digit
        for (int i = 1; i < value.Length*5; i++) { //loop once for each bit, only do work on boundary bits thought
          if (0 == i % 5) { //we need the next digits bits
            buffer <<= 5;
            buffer |= value_lookup[value[i/5]];
          }
          if (0 == i % 8) { //we have another byte worth of bits
            //(i/5+1)*5-i) is the number of low order bits that we can't use yet
            secret[i / 8 - 1] = (byte)(buffer>>(i/5+1)*5-i);
          }
        };
        //don't forget the last byte
        secret[value*5/8-1] = (byte)buffer;
        K = secret;
      }
      //TODO make a get property here
    }

    /// <summary>
    /// Convert the key to and from it's hex string representation.
    /// </summary>
    public string hex_secret{
      set{
        byte[] secret = new byte[value.Length/2];
        for (int i = 0; i < value.Length; i += 2)
          secret[i/2]=(byte)Int16.Parse(value.Substring (i,2),NumberStyles.AllowHexSpecifier);
      }
      get{
        return BitConverter.ToString(K).Replace("-","");
      }
      
    }
    
    /// <summary>
    /// Truncate the hash as specified in RFC 4226.
    /// </summary>
    protected int Truncate() {
      int result = 0;
      byte[] hash = this.Hash; //just compute the hash once here
      int offset = hash[19] & 0x0f;
      for (int i = 0; i < 4; i++) {
        result |= ((int)(hash[3 - i + offset])) << (i*8);
      }
      return result;
    }

    /// <summary>
    /// The hotp value. Really just forward to truncate.
    /// </summary>
    public int Value {
      get { return Truncate (); }
    }
  }

  class TOTP: HOTP {
    public const long DefaultTimeStep = 30;
    
    /// <summary>
    /// The timestep, with variable name chosen by rfc 6238.
    /// </summary>
    private long X;
    /// <summary>
    /// How long each password is good for in seconds.
    /// </summary>
    public long TimeStep{
      get{
        return X;
      }
      set{
        X=value;
      }
    }
    
  }
  class MainClass {
    /// <summary>
    /// Time zero. The unix epoch.
    /// </summary>
    protected static readonly long T0 = 0;
    protected static readonly DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
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



    public static int Main (string[] args) {
      if (0==args.Length) {
				Console.WriteLine ("usage: yotp secret1 secret2 ...");
				return 1;
			}
      foreach (string secret in args) {
        //checking for mods is far from foolproof, but better than checking the length
        if(0 == secret.Length%5)
          K = hex_key (secret);
        else if(0 == secret.Length%8)
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
