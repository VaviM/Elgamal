using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace ElGamal
{
    /// <summary>
    /// Криптосистема Эль-Гамаля
    /// </summary>
    class ElGamal
    {
        /// <summary>
        /// Модуль
        /// </summary>
        public decimal P;
        /// <summary>
        /// Генератор (примитивный элемент)
        /// </summary>
        public decimal g;
        /// <summary>
        /// Открытый ключ
        /// </summary>
        public decimal KOpen;
        /// <summary>
        /// Закрытый ключ
        /// </summary>
        private decimal KClose;
        /// <summary>
        /// Инициализирует экземпляр значениями ключей
        /// </summary>
        public ElGamal()
        {
            KeyGen();
        }
        /// <summary>
        /// Инициализирует экземпляр значениями ключей по указанному модулю
        /// </summary>
        /// <param name="p"></param>
        public ElGamal(ulong p)
        {
            P = p; /* (x,p)=1 */
            KeyGen(P);
        }
        /// <summary>
        /// Генерация ключей
        /// </summary>
        protected void KeyGen()
        {
            P = CreateBigPrime(10);
            g = TakePrimitiveRoot(P);
            KClose = 2;
            while (GCD(KClose, P) != 1)
            {
                KClose = CreateBigPrime(10) % (P - 1);
            }
            KOpen = PowMod(g, KClose, P);
        }
        /// <summary>
        /// Генерация ключей
        /// </summary>
        protected void KeyGen(decimal prime)
        {
            g = TakePrimitiveRoot(prime);
            Random rand = new Random();
            KClose = 2;
            while (GCD(KClose, prime) != 1)
            {
                KClose = (rand.Next(1, Int32.MaxValue) * rand.Next(1, Int32.MaxValue)) % (prime - 1);
            }
            KOpen = PowMod(g, KClose, prime);
        }
        /// <summary>
        /// Поиск наибольшего общего делителя
        /// </summary>
        /// <param name="a">Первое число</param>
        /// <param name="b">Второе число</param>
        /// <returns>НОД</returns>
        public static decimal GCD(decimal a, decimal b)
        {
            if (b == 0)
                return a;
            else
                return GCD(b, a % b);
        }
        /// <summary>
        /// Производит поиск генератора всей группы
        /// </summary>
        /// <param name="primeNum">Порядок группы</param>
        /// <returns>Генератор</returns>
        protected decimal TakePrimitiveRoot(decimal primeNum)
        {
            for (ulong i = 0; i < primeNum; i++)
                if (IsPrimitiveRoot(primeNum, i))
                    return i;
            return 0;
        }
        /// <summary>
        /// Проверка на примитивность
        /// </summary>
        /// <param name="p">Порядок</param>
        /// <param name="a">Элемент</param>
        /// <returns></returns>
        public bool IsPrimitiveRoot(decimal p, decimal a)
        {
            if (a == 0 || a == 1)
                return false;
            decimal last = 1;
            HashSet<decimal> set = new HashSet<decimal>();
            for (ulong i = 0; i < p - 1; i++)
            {
                last = (last * a) % p;                
                if (set.Contains(last)) // Если повтор
                    return false;
                set.Add(last);
            }
            return true;
        }
        /// <summary>
        /// Шифрование
        /// </summary>
        /// <param name="message">Сообщение</param>
        /// <returns>Зашифрованный текст</returns>
        public List<decimal[]> Encrypting(string message)
        {
            byte[] binary = Encoding.UTF8.GetBytes(message);
            List<decimal[]> ciphermessage = new List<decimal[]>(); //Хранение шифртекста - пары чисел 
            Random rand = new Random();
            decimal[] pair = new decimal[2];
            decimal k = 0;
            for (int i = 0; i < binary.Length; i++)
            {
                k = (rand.Next(1, Int16.MaxValue) * rand.Next(1, Int16.MaxValue))%(P-1);
                pair = new decimal[2];
                pair[0] = PowMod(g, k, P);
                pair[1] = (PowMod(KOpen, k, P) * binary[i]) % P;
                ciphermessage.Add(pair);
            }
            return ciphermessage;
        }
        /// <summary>
        /// Расшифрование
        /// </summary>
        /// <param name="ciphermesage">Зашифрованное сообщение</param>
        /// <returns>Расшифрованный текст</returns>
        public string Decrypting(List<decimal[]> ciphermesage)
        {
            string plain = "";
            byte n;
            for (int i = 0; i < ciphermesage.Count; i++)
            {
                n = (byte)((PowMod((decimal)EuclideanAlgorithm(P, ciphermesage[i][0]), KClose, P) * ciphermesage[i][1]) % P);
                plain += Encoding.ASCII.GetChars(new byte[] { n})[0];
            }
            return plain;
        }
        /// <summary>
        /// Вычисление обратного числа. Расширенный алгоритм Евклида
        /// </summary>
        /// <param name="Fi">Значение ф(N)</param>
        /// <param name="OpenKey">Открытый ключ</param>
        public decimal EuclideanAlgorithm(decimal module, decimal element)
        {
            decimal inverse =0;
            decimal w1 = 0, w3 = module, r1 = 1, r3 = element; //Инициализация
            decimal q = (decimal)Math.Floor((w3 /r3));
            decimal cr1, cr3;
            while (r3 != 1)
            {
                cr1 = r1;
                cr3 = r3;
                r1 = w1 - r1 * q;
                r3 = w3 - r3 * q;
                w1 = cr1;
                w3 = cr3;
                //q = (r3 == 0) ? 0 : w3 / r3;
                q = Math.Floor(w3 / r3);
            }

            inverse = r1;
            if (inverse < 0) //Устранение отрицательности 
            {
                inverse += module;
            }
            //if ((CloseKey * OpenKey - 1) % Fi == 0) //Проверка правильности подбора ключей
           
            return inverse;
        }
        /// <summary>
        /// Определение большого простого числа(генерация)
        /// </summary>
        /// <param name="numDec">Количество десятичных знаков</param>
        /// <returns>Число</returns>
        public ulong CreateBigPrime(short numDec)
        {
            ulong N=1;
            Random rand = new Random(DateTime.Now.Millisecond);
            while (Convert.ToString(N).Length < numDec || !isPrime(N))
            {
                N = (ulong)(rand.Next(0, int.MaxValue) * rand.Next(0, int.MaxValue)) - 1;
            }
            return N;
        }
        /// <summary>
        /// Проверка на простоту (примитивная)
        /// </summary>
        /// <param name="n">Число</param>
        /// <returns>true, если простое, false - если нет</returns>
        public bool isPrime(ulong n)
        {
            for (ulong i = 2; i < n / 2 + 1; i++)
            {
                if ((n % i) == 0) return false;
            }
            return true;
        }
        /// <summary>
        /// Алгоритм быстрого возведения в степень по модулю
        /// </summary>
        /// <param name="number">Число</param>
        /// <param name="pow">Степень</param>
        /// <param name="module">Модуль</param>
        /// <returns>Значение по модулю</returns>
        public static decimal PowMod(decimal number, decimal pow, decimal module)
        {
            string q = Convert.ToString((long)pow, 2); //Двоичное представление степени
            BigInteger s = 1, c = (BigInteger)number; //Инициализация
            for (int i = q.Length - 1; i >= 0; i--)
            {
                if (q[i] == '1')
                {
                    s = (s * c) % (BigInteger)module;
                }
                c = (c * c) % (BigInteger)module;
            }
            return (decimal)s;
        }
    }
}
