using System;

namespace C25519
{
    class KeyExchange
    {
        public C25519Key key1 { get; set; }
        public C25519Key key2 { get; set; }

        public KeyExchange()
        {
            key1 = new C25519Key();
            key2 = new C25519Key();
        }

        public bool ValidateKeyExchange(C25519Point pubKey1, C25519Point pubKey2)
        {
            var v1 = C25519Point.Multiply(key1.X, pubKey2.X, pubKey2.Y, C25519Point.P);
            var v2= C25519Point.Multiply(key2.X, pubKey1.X, pubKey1.Y, C25519Point.P);
            return (v1.X == v2.X && v1.Y == v2.Y);
        }
    }
}

