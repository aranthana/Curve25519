using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace C25519
{
    public static class EcDSA
    {
        public static (BigInteger R, BigInteger S) Sign(byte[] message, C25519Key key)
        {
            BigInteger k, r, s;
            do
            {
                do
                {
                    k = key.Generate(BigInteger.One);
                    r = C25519Key.ScalarMultiplication(k, C25519Point.G.X, C25519Point.G.Y, C25519Point.P).X % C25519Point.N;
                } while (r == BigInteger.Zero);

                var m = GetM(message);
                var kInv = k.PrimeInv(C25519Point.N);
                s = kInv * (m + (key.X * r) % C25519Point.N) % C25519Point.N;
            } while (s == BigInteger.Zero);

            return (r, s);
        }

        public static bool Verify(byte[] message, BigInteger r, BigInteger s, C25519Key key)
        {
            return Verify(GetM(message), r, s, key);
        }

        public static bool Verify(BigInteger m, BigInteger r, BigInteger s, C25519Key key)
        {
            var w = s.PrimeInv(C25519Point.N);
            var u1 = m * w % C25519Point.N;
            var u2 = r * w % C25519Point.N;
            C25519Point p1 = C25519Key.ScalarMultiplication(u1, C25519Point.G.X, C25519Point.G.Y, C25519Point.P);
            C25519Point p2 = C25519Key.ScalarMultiplication(u2, key.Y.X, key.Y.Y, C25519Point.P);
            var x_r = p1.X;
            var y_r = p1.Y;
            C25519Key.AddPointsFiniteField(ref x_r, ref y_r,p2.X,p2.Y, C25519Point.P);
            var v = (new C25519Point(x_r, y_r) ).X % C25519Point.N;
            return v == r;
            
        }
        public static (C25519Point R, BigInteger S) SignEdDSA(byte[] message, C25519Key key)
        {
            BigInteger r, s;
            C25519Point R;

                do
                {
                    // Instead of random r instead of hash(hash(privateKey) + msg) mod q
                    r = key.Generate(BigInteger.One);
                    R = C25519Key.ScalarMultiplication(r, C25519Point.G.X, C25519Point.G.Y, C25519Point.P);
            } while (R.X % C25519Point.N == BigInteger.Zero);
            
            byte[] encodedR = EncodePoint(R);
            byte[] encodedPubKey = EncodePoint(key.Y);
            byte[] rv = encodedR.Concat(encodedPubKey).Concat(message).ToArray();
        
            // h = hash(R + pubKey + msg) mod q
            var h = GetMEd(rv);
            // s = (r + h * privKey) mod q
            s = (r + (key.X * h) % C25519Point.N) % C25519Point.N;

            return (R, s);
        }

        public static byte[] EncodePoint(C25519Point point)
        {
            var x_lsb = point.X & 1;
            // Encode the y-coordinate as a little-endian string of 32 octets.
            byte[] yByteArray = point.Y.ToByteArray(true, false).PadRight(32);
            int new_msb = 0;
            if (x_lsb == 1)
            {
                int mask = 128;
                new_msb = yByteArray[31] | mask;
            }
            if (x_lsb == 0)
            {
                int mask = 127;
                new_msb = yByteArray[31] & mask;
            }
            // Copy the least significant bit of the x - coordinate to the most significant bit of the final octet.
            yByteArray[31] = (byte)new_msb;
            return yByteArray;
        }


      

        public static bool VerifyEdDSA(byte[] m, C25519Point R, BigInteger s, C25519Key key)
        {
            byte[] encodedR = EncodePoint(R);
            byte[] encodedPubKey = EncodePoint(key.Y);
            byte[] rv = encodedR.Concat(encodedPubKey).Concat(m).ToArray();
            // h = hash(R + pubKey + msg) mod q
            var h = GetMEd(rv) % C25519Point.N;
            var p1 = C25519Key.ScalarMultiplication(s, C25519Point.G.X, C25519Point.G.Y, C25519Point.P);
            var p2_2 = C25519Key.ScalarMultiplication(h, key.Y.X, key.Y.Y, C25519Point.P);
            var x_r = R.X;
            var y_r = R.Y;
            C25519Key.AddPointsFiniteField(ref x_r, ref y_r, p2_2.X, p2_2.Y, C25519Point.P);
            var p2 = new C25519Point(x_r, y_r);
            //var p2 = R + C25519Key.ScalarMultiplication(h, key.Y.X, key.Y.Y, C25519Point.P);
           
            return (p1.X == p2.X && p1.Y ==p2.Y);
        }

       

        public static BigInteger GetMEd(byte[] message)
        {
            return new BigInteger(HashSHA512(message).ToArray(), true, false);
        }


        public static BigInteger GetM(byte[] message)
        {
            return new BigInteger(Hash(message).Take(C25519Point.N.GetByteCount(true)).ToArray(), true, true);
        }
        public static byte[] Hash(byte[] message)
        {
            using (var hasher = new SHA256Managed())
            {
                return hasher.ComputeHash(message);
            }

        }
        public static byte[] HashSHA512(byte[] message)
        {
            using (var hasher = new SHA512Managed())
            {
                return hasher.ComputeHash(message);
            }

        }
        public static BigInteger PrimeInv(this BigInteger value, BigInteger p)
        {
            return BigInteger.ModPow(value, p - 2, p);
        }
        public static T[] PadLeft<T>(this T[] data, int length, T padding = default) where T : struct
        {
            if (data.Length >= length)
                return data;

            var newArray = new T[length];
            Array.Copy(data, 0, newArray, length - data.Length, data.Length);

            return newArray;
        }

        public static T[] PadRight<T>(this T[] data, int length, T padding = default) where T : struct
        {
            if (data.Length >= length)
                return data;

            var newArray = new T[length];
            Array.Copy(data, 0, newArray, 0, data.Length);

            return newArray;
        }
    }
}
