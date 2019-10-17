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
            ElGamal q = new ElGamal(20996023);
            Console.WriteLine($"P: {q.P}\ng: {q.g}\nOpen: {q.KOpen}");//Close: {q.KClose}\n
            string message = "Valentina Maslennikova";
            Console.WriteLine("Input text: "+message);
            List<decimal[]> text = q.Encrypting(message);
            Console.WriteLine("Encrypted...");
            for (int i = 0; i < text.Count; i++)
            {
                Console.Write("{" + text[i][0] + ", " + text[i][1] + "}, ");
            }
            Console.WriteLine("\nCryptoanalisis...");
            Console.WriteLine("Decrypted..."+ElGamal.GetPlainFromCipher(text, q.P, q.g, q.KOpen));
            Console.WriteLine("Decrypted with key...");
            Console.WriteLine(q.Decrypting(text));

        }
    }
}
