using System;
using System.Numerics;

namespace C25519
{
    public class C25519Point
    {
        public BigInteger X { get; set; }
        public BigInteger Y { get; set; }

        //Prime = (BigInteger)(Math.Pow(2, 256) - Math.Pow(2, 32) - Math.Pow(2, 9) - Math.Pow(2, 8) - Math.Pow(2, 7) - Math.Pow(2, 6) - Math.Pow(2, 4) - 1);
        public static BigInteger P = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819949");
        public static BigInteger A = BigInteger.Parse("19298681539552699237261830834781317975544997444273427339909597334573241639236");
        public static BigInteger N = BigInteger.Parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");

        public static C25519Point G = GeneraterPoint();

        private const int b = 0;

        public C25519Point()
        {
           
           
        }
        public C25519Point(BigInteger x, BigInteger y)
        {
            X = x;
            Y = y;
        }
      
      
        private static C25519Point GeneraterPoint()
        {
            var gX = "19298681539552699237261830834781317975544997444273427339909597334652188435546";
             var gY = "14781619447589544791020593568409986887264606134616475288964881837755586237401";
            //var gX = "13";
            //var gY = "19";
            return new C25519Point(BigInteger.Parse(gX), (BigInteger.Parse(gY)));


        }
    }
}
