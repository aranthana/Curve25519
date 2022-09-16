using System;
using System.Numerics;
using System.Security.Cryptography;


namespace C25519
{

    class C25519Key
    {
        public BigInteger X { get; private set; }
        public C25519Point Y { get; private set; }

        public C25519Key()
        {
           
            X = new BigInteger(RandomNumberGenerator.GetBytes(32), true, true);
            Y = C25519Point.Multiply(X, C25519Point.G.X, C25519Point.G.Y, C25519Point.P);
        }
    }
}
