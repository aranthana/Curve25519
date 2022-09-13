using System;
using System.Text;
using System.Numerics;
using System.Security.Cryptography;


namespace C25519
{
    public  class C25519Key
    {
        public BigInteger X { get; private set; }
        public C25519Point Y { get; private set; }

       
        public  BigInteger Field { get; }
        private  int Bytes { get => Field.GetByteCount(true); }
        private RNGCryptoServiceProvider rdm;

        public C25519Key()
        {
            Field = C25519Point.N;
            X =  Generate(BigInteger.One);
            Y = ScalarMultiplication(X, C25519Point.G.X, C25519Point.G.Y, C25519Point.P);


        }


        public   BigInteger Generate(BigInteger? min = null)
        {
            var bytes = new byte[Bytes];
            BigInteger number;
            rdm = new RNGCryptoServiceProvider();
            do
            {
                rdm.GetBytes(bytes);
                number = new BigInteger(bytes, true, true);
            }
            while (number >= Field || (min.HasValue && number < min.Value));
            
            return number;
        }

        public  static C25519Point ScalarMultiplication(BigInteger d, BigInteger x, BigInteger y, BigInteger prime)
        {
            BigInteger x_r = x;
            BigInteger y_r = y;
           List<BigInteger> binaryList = ConvertToBinary(d);
            int zeroCount = 0;
            bool firstOne = true;
            for (int i = 0; i < binaryList.Count; i++)
            {

                if (binaryList[i] == 1)
                {
                    while (zeroCount > 0)
                    {
                        //DoubleThePoint(ref x, ref y);
                        DoubleThePointFiniteFiled(ref x, ref y, prime);
                        zeroCount--;
                    }
                    if (firstOne)
                    {
                        firstOne = false;
                        x_r = x;
                        y_r = y;
                    }
                    else
                    {
                        //DoubleThePoint(ref x, ref y);
                       DoubleThePointFiniteFiled(ref x, ref y, prime);
                        //AddDifferentPoints(ref x_r, ref y_r, x, y);
                        AddPointsFiniteField(ref x_r, ref y_r, x, y, prime);
                    }
                }
                else
                    zeroCount++;
            }
           return new C25519Point(x_r, y_r);


        }
        private static List<BigInteger> ConvertToBinary(BigInteger n)
        {
            List<BigInteger> binaryList = new List<BigInteger>();
            do
            {
                binaryList.Add(n % 2);
                n = n / 2;
            } while (n != 0);
            return binaryList;
        }
        public static void AddPointsFiniteField(ref BigInteger x_r, ref BigInteger y_r, BigInteger x, BigInteger y, BigInteger prime)
        {

            //Console.WriteLine("Points to be added : " + x_r + "," + y_r + " + " + x + "," + y);
            BigInteger m = Mod((y_r - y) * ModInversCalculation(x_r - x, prime), prime);
            x_r = Mod((m * m) - (x_r + x), prime);
            y_r = Mod(m * (x - x_r) - y, prime);
            //Console.WriteLine("Added point and generated : " + x_r + " ," + y_r);
        }

        private static void DoubleThePointFiniteFiled(ref BigInteger x, ref BigInteger y, BigInteger prime)
        {
            //WriteLine("Points to be doubled : " + x + "," + y);
            BigInteger oldX = x;
            BigInteger m = Mod((3 * x * x + C25519Point.A) * ModInversCalculation(2 * y, prime), prime);
            x = Mod(m * m - (2 * x), prime);
            y = Mod(m * (oldX - x) - y, prime);
            //WriteLine("Doubled point : " + x + "," + y);
        }

       
        private static BigInteger ModInversCalculation(BigInteger a, BigInteger m)
        {

            BigInteger g = Gcd(a, m);
            if (g != 1) { }
            //WriteLine("Inverse doesn't exist");
            else
            {
                // If a and m are relatively
                // prime, then modulo inverse
                // is a^(m-2) mode m
                //WriteLine("Modular multiplicative inverse is "+Power(a, m - 2, m));
            }
            return Power(a, m - 2, m);
        }

        // To compute x^m-2 under
        // modulo m
        static BigInteger Power(BigInteger x, BigInteger y, BigInteger m)
        {
            if (y == 0)
                return 1;

            BigInteger p = Power(x, y / 2, m) % m;
            p = (p * p) % m;
            if (y % 2 == 0)
                return p;
            else
                return (x * p) % m;
        }

        // Function to return
        // gcd of a and b
        static BigInteger Gcd(BigInteger a, BigInteger b)
        {
            if (a == 0)
                return b;
            return Gcd(b % a, a);
        }
        private static BigInteger Mod(BigInteger a, BigInteger p)
        {
            BigInteger m = a % p;
            return m < 0 ? m + p : m;
        }

       


    }
}
