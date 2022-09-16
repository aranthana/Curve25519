using System;
using System.Text;
using System.Numerics;
using System.Diagnostics;
using System.Threading;



namespace C25519
{
    class Program
    {
        public static void Main(string[] args)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();

            C25519Key key = new();
            var message = "Hello World!!!!";
            byte[] encodedMsg = Encoding.UTF8.GetBytes(message);
            watch.Stop();

            watch.Restart();
            var (r, s) = DSA.Sign(encodedMsg, key);
            byte[] signature = r.ToByteArray(true, true).PadLeft(32).Concat(s.ToByteArray(true, true).PadLeft(32)).ToArray();
            watch.Stop();
            Console.WriteLine("Elapsed Time is {0} ms", watch.ElapsedMilliseconds);
            //Console.WriteLine("signature {0}", BitConverter.ToString(signature));

            watch.Restart();
            if (signature == null || signature.Length != 64)
                Console.WriteLine("invalid signature");
            else
            {

                r = new BigInteger(signature.Take(32).ToArray(), true, true);
                s = new BigInteger(signature.Skip(32).ToArray(), true, true);

                Console.WriteLine("Valid signature {0}", DSA.Verify(encodedMsg, r, s, key));
            }

            watch.Stop();
            Console.WriteLine("Elapsed Time is {0} ms", watch.ElapsedMilliseconds);

            watch.Restart();

            var (R, S) = DSA.SignEdDSA(encodedMsg, key);
            byte[] signatureEd = R.X.ToByteArray(true, false).PadRight(32).Concat(R.Y.ToByteArray(true, false).PadRight(32))
               .Concat(S.ToByteArray(true, false).PadRight(32)).ToArray();
            watch.Stop();
            Console.WriteLine("Elapsed Time is {0} ms", watch.ElapsedMilliseconds);
            //Console.WriteLine("signature Ed {0}", BitConverter.ToString(signatureEd));

            watch.Restart();
            if (signatureEd == null || signatureEd.Length != 96)
                Console.WriteLine("invalid signature");
            else
            {
                byte[] rByteArray = signatureEd.Take(64).ToArray();
                var r_x = new BigInteger(rByteArray.Take(32).ToArray(), true, false);
                var r_y = new BigInteger(rByteArray.Skip(32).ToArray(), true, false);
                var s1 = new BigInteger(signatureEd.Skip(64).ToArray(), true, false);
                C25519Point rPoint = new C25519Point(r_x, r_y);

                Console.WriteLine("Valid signature {0}", DSA.VerifyEdDSA(encodedMsg, rPoint, s1, key));
            }
            watch.Stop();
            Console.WriteLine("Elapsed Time is {0} ms", watch.ElapsedMilliseconds);



            watch.Restart();
            Cipher cipher = Cipher.Encrypt(encodedMsg.PadLeft(32), key);
            
            //Console.WriteLine("encrypted {0} {1} {2}", cipher.C1.X, cipher.C1.Y, BitConverter.ToString(cipher.C2));
            var mTag = Cipher.Decrypt( key, cipher);
            //Console.WriteLine("{0} after Decrypted {1}",BitConverter.ToString(encodedMsg.PadLeft(32)) ,BitConverter.ToString(mTag));
            watch.Stop();
            Console.WriteLine("Elapsed Time is {0} ms", watch.ElapsedMilliseconds);

            
            KeyExchange keyExchange = new KeyExchange();
            watch.Restart();
            Console.WriteLine("Key exchnage "+keyExchange.ValidateKeyExchange(keyExchange.key1.Y , keyExchange.key2.Y));
            watch.Stop();
            Console.WriteLine("Elapsed Time is {0} ms", watch.ElapsedMilliseconds);
        }










    }




}


