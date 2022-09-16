using System;
using System.Numerics;
using System.Security.Cryptography;

namespace C25519
{
    class Cipher
    {

        public C25519Point C1 { get; set; }
        public byte[] C2 { get; set; }

        public Cipher(C25519Point c1, byte[] c2)
        {
            C1 = c1;
            C2 = c2;
        }

        public static Cipher Encrypt(byte[] m, C25519Key key)
        {

            var k = new BigInteger(RandomNumberGenerator.GetBytes(32), true, true);
            var c1 = C25519Point.Multiply(k, C25519Point.G.X, C25519Point.G.Y, C25519Point.P);
            C25519Point p = C25519Point.Multiply(k, key.Y.X, key.Y.Y, C25519Point.P);
            var c2 = XOR(DSA.Hash(ToByteArray(p)), m);

            return new Cipher(c1, c2);

        }

        public static byte[] Decrypt(C25519Key key, Cipher c)
        {
            return XOR(DSA.Hash(ToByteArray(C25519Point.Multiply(key.X, c.C1.X, c.C1.Y, C25519Point.P))), c.C2);
        }

        private static byte[] XOR(byte[] data1, byte[] data2)
        {

            if (data1.Length != data2.Length)
                throw new ArgumentException();

            byte[] result = new byte[data1.Length];
            for (int i = 0; i < data1.Length; i++)
                result[i] = (byte)(data1[i] ^ data2[i]);

            return result;
        }

        public static byte[] ToByteArray(C25519Point p) => ToByteArray(p, false);

        public static byte[] ToByteArray(C25519Point point, bool compact)
        {
            var bytes = (int)Math.Ceiling(32 / 8.0);

            if (!compact)
                return point.X.ToByteArray(true, true).PadLeft(bytes)
                    .Concat(point.Y.ToByteArray(true, true).PadLeft(bytes)).ToArray();

            var val = (point.X << 1) | (point.X < 0 ? 1 : 0);
            return val.ToByteArray(true, true).PadLeft(bytes);
        }




    }
}

