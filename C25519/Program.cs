using System;
using System.Text;
using System.Numerics;



namespace C25519
{
    class Program
    {
        public static void Main(string[] args)
        { 
            
            C25519Key key = new C25519Key();
            var message = "Hello World!!!!";
            byte[] encodedMsg = Encoding.UTF8.GetBytes(message);
            var (r, s) = EcDSA.Sign(encodedMsg, key);
            byte[] signature = r.ToByteArray(true, true).PadLeft(32).Concat(s.ToByteArray(true, true).PadLeft(32)).ToArray();
            Console.WriteLine("signature {0}",BitConverter.ToString(signature));
            if (signature == null || signature.Length != 64)
                Console.WriteLine("invalid signature");
            else
            {

                r = new BigInteger(signature.Take(32).ToArray(), true, true);
                s = new BigInteger(signature.Skip(32).ToArray(), true, true);
              
                Console.WriteLine("Valid signature {0}", EcDSA.Verify(encodedMsg, r, s, key)) ;
            }




            var (R, S) = EcDSA.SignEdDSA(encodedMsg, key);
            byte[] signatureEd = R.X.ToByteArray(true, false).PadRight(32).Concat(R.Y.ToByteArray(true, false).PadRight(32))
               .Concat(S.ToByteArray(true, false).PadRight(32)).ToArray();
            Console.WriteLine("signature Ed {0}", BitConverter.ToString(signatureEd));
            if (signatureEd == null || signatureEd.Length != 96)
                Console.WriteLine("invalid signature");
            else
            { 
                byte[] rByteArray = signatureEd.Take(64).ToArray();
                var r_x = new BigInteger(rByteArray.Take(32).ToArray(), true, false);
                var r_y = new BigInteger(rByteArray.Skip(32).ToArray(), true, false);
                var s1 = new BigInteger(signatureEd.Skip(64).ToArray(), true, false);
                C25519Point rPoint = new C25519Point(r_x, r_y);
                
                Console.WriteLine("Valid signature {0}", EcDSA.VerifyEdDSA(encodedMsg, rPoint, s1, key));
            }
        }

      








    }




}


