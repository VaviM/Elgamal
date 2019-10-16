using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ElGamal
{
    class Program
    {
        static void Main(string[] args)
        {
            // ElGamal q = new ElGamal(2147483647);//(20996023);//(7687);
            /*ElGamal q = new ElGamal(20996023);
            Console.WriteLine($"P: {q.P}\ng: {q.g}\nOpen: {q.KOpen}");//Close: {q.KClose}\n
            string message = "Andrey";//"Valentina Maslennikova";
            Console.WriteLine("Input text: "+message);
            List<decimal[]> text = q.Encrypting(message);
            Console.WriteLine("Encrypted...");
            for (int i = 0; i < text.Count; i++)
            {
                Console.Write("{" + text[i][0] + ", " + text[i][1] + "}, ");
            }
            Console.Write("\nDecrypted...\n");
            Console.WriteLine(q.Decrypting(text));*/
            //Console.WriteLine(ElGamal.RhoPolard(10, 64, 107));
            //decimal x = ElGamal.MatchingAlgorithm(3, 9897979, 20996023);
            //Console.WriteLine("x = "+x);
            // decimal m = 4570174 / ElGamal.PowMod(9, x, 20996023) ;
            //decimal m =  (ElGamal.PowMod(ElGamal.EuclideanAlgorithm(20996023,9), x, 20996023)* 4570174)% 20996023;

            //m = ElGamal.EuclideanAlgorithm(20996023, m);
           //Console.WriteLine("m = " + m);

        }
    }
}
