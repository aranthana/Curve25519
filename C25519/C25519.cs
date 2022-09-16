using System.Numerics;

namespace C25519
{
    public class C25519Point
    {
        public BigInteger X { get; private set; }
        public BigInteger Y { get; private set; }

        public static BigInteger P = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819949");
        public static readonly BigInteger A = BigInteger.Parse("19298681539552699237261830834781317975544997444273427339909597334573241639236");
        public static BigInteger N = BigInteger.Parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");
        private static BigInteger gX = BigInteger.Parse("19298681539552699237261830834781317975544997444273427339909597334652188435546");
        private static BigInteger gY = BigInteger.Parse("14781619447589544791020593568409986887264606134616475288964881837755586237401");
        public static C25519Point G = GeneraterPoint();

        private const int B = 0;

        public C25519Point(BigInteger x, BigInteger y)
        {
            X = x;
            Y = y;
        }

        private static C25519Point GeneraterPoint()
        { 
            return new C25519Point(gX, gY);
        }

        public static C25519Point Multiply(BigInteger d, BigInteger x, BigInteger y, BigInteger prime)
        {
            BigInteger x_r = x;
            BigInteger y_r = y;
            bool isFirstOne = true;
            while (d > 0)
            {
                if ((d & 0).Equals(0))
                {
                    if (isFirstOne)
                    {
                        isFirstOne = false;
                        x_r = x;
                        y_r = y;
                    }
                    else
                        AddPoints(ref x_r, ref y_r, x, y, prime);
                }
                DoubleThePoint(ref x, ref y, prime);
                d = d >> 1;
            }

            return new C25519Point(x_r, y_r);


        }

        public static void AddPoints(ref BigInteger x_r, ref BigInteger y_r, BigInteger x, BigInteger y, BigInteger prime)
        {
            var inv = (x_r - x).PrimeInv(prime);
            BigInteger m = Mod((y_r - y) * inv, prime);
            x_r = Mod((m * m) - (x_r + x), prime);
            y_r = Mod(m * (x - x_r) - y, prime);
        }

        private static void DoubleThePoint(ref BigInteger x, ref BigInteger y, BigInteger prime)
        {
            BigInteger oldX = x;
            BigInteger m = Mod((3 * x * x + A) * ((2 * y).PrimeInv(prime)), prime);
            x = Mod(m * m - (2 * x), prime);
            y = Mod(m * (oldX - x) - y, prime);
        }

        private static void Double(ref BigInteger x, ref BigInteger y, BigInteger prime)
        {
           
            BigInteger A1 = x * x;
            BigInteger B1 = 3 * A1;
            BigInteger C = B1+ A;
            BigInteger D = 2 * x;
            BigInteger Z = 2 * y;
            BigInteger F = D * Z;
            BigInteger X1 = C - F;
            BigInteger H = x - X1;
            BigInteger I = C * H;
            BigInteger Y1 = H - (y * Z);

            BigInteger oldX = x;
            BigInteger m = Mod((3 * x * x + A) * ((2 * y).PrimeInv(prime)), prime);
            x = Mod(m * m - (2 * x), prime);
            y = Mod(m * (oldX - x) - y, prime);
        }


        private static BigInteger Mod(BigInteger a, BigInteger p)
        {
            BigInteger m = a % p;
            return m < 0 ? m + p : m;
        }

    }
}
