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
        public static decimal EuclideanAlgorithm(decimal module, decimal element)
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
        /// Дискретное логарифмирование a^x = b(mod p)
        /// </summary>
        /// <param name="a">Число в степени</param>
        /// <param name="q">Свободный элемент</param>
        /// <param name="p">Модуль</param>
        /// <returns>Показатель степени</returns>
        public static decimal MatchingAlgorithm(decimal a, decimal b, decimal p)
        {
            decimal x=0,
                H = (long)Math.Sqrt(Decimal.ToUInt64(p)) + 1;
            decimal c = PowMod(a, H, p);
            List<decimal> table_0 = new List<decimal>(),
                table_1 = new List<decimal>();
            table_1.Add((b % p));
            for (long i = 1; i <= H; i++)
            {
                table_0.Add(PowMod(c, i, p));
                table_1.Add(((PowMod(a, i, p) * b) % p));
            }
            decimal q;
            for (short i = 0; i < table_1.Count; i++)
            {
                q = table_0.IndexOf(table_1[i]);
                if ( q > 0)
                {
                    x = ((q+1) * H - i);//% (p - 1);
                    break;
                }
            }
            return x;
        }
        /// <summary>
        /// a^x = b(mod p)
        /// </summary>
        /// <param name="a"></param>
        /// <param name="q"></param>
        /// <param name="p"></param>
        /// <returns></returns>
        public static decimal RhoPolard(decimal a, decimal b, decimal p)
        {
            List<decimal> u = new List<decimal>(),
                v = new List<decimal>(),
                z = new List<decimal>();
            List<int> ii = new List<int>();
            decimal x = 0;
            int i2;
            u.Add(0);
            v.Add(0);
            z.Add(1);
            int i = 0;
            while (true)
            {
                if (z[i] > 0 && z[i] < p / 3)
                {
                    u.Add((u[i] + 1) % (p - 1));
                    v.Add(v[i] % (p - 1));
                }
                if (z[i] > p / 3 && z[i] < 2 * (p / 3))
                {
                    u.Add((2 * u[i]) % (p - 1));
                    v.Add((2 * v[i]) % (p - 1));
                }
                if (z[i] > 2 * (p / 3) && z[i] < p)
                {
                    u.Add(u[i] % (p - 1));
                    v.Add((v[i] + 1) % (p - 1));
                }
                z.Add((PowMod(b, u[u.Count - 1], p - 1) * PowMod(a, v[v.Count - 1], p - 1)) % (p - 1));
                i++;
                if (z[i] > 0 && z[i] < p / 3)
                {
                    z[i] = (b * z[i]) % p;
                }
                if (z[i] > p / 3 && z[i] < 2 * (p / 3))
                {
                    z[i] = (z[i] * z[i]) % p;
                }
                if (z[i] > 2 * (p / 3) && z[i] < p)
                {
                    z[i] = (a * z[i]) % p;
                }
                i2 = -1;
                /*for (int h = 0; h < z.Count - 2; h++)
                {
                    if (z[i] == z[h])
                    {
                        i2 = h;
                        break;
                    }
                }
                if (i2 != -1)
                {
                    break;
                }*/
                i2 = (int)Math.Ceiling((double)i / 2);
                //i2 = (int)Math.Floor((double)i / 2);
                if (i >= 2 && z[i2] == z[i])
                {
                    ii.Add(i2);
                    if (GCD(u[i] - u[i2], p - 1) == 1)
                    {
                        x = (EuclideanAlgorithm(p - 1, (u[i] - u[i2])) * (v[i2] - v[i]));
                        x = (x < 0) ? ((p - 1) + x) % (p - 1) : x % (p - 1);
                    }
                    //x = (v[i / 2] - v[i]) / (u[i] - u[i / 2]);
                    if (ii.Count >= 3)
                    {
                        break;
                    }
                }
            }
            if(GCD(u[i] - u[i2], p - 1) == 1)
            {
                x = EuclideanAlgorithm(p - 1, (u[i] - u[i2]));// * (v[i2] - v[i]));
                x = (x < 0) ? ((p - 1) + x) % (p - 1) : x % (p - 1);
            }
            /*if(GCD(u[i]-u[i/2], p - 1) == 1)
            {
                for (int j = 0; j < p-1; j++)
                {
                    if ((j * (u[i] - u[i / 2])) % (p - 1) == 1)
                    {
                        x = j * (v[i / 2] - v[i]);
                        break;
                    }
                }
            }*/
           /* if (GCD(u[i] - u[i2], p - 1) == 1)
            {
                for (int j = 0; j < p - 1; j++)
                {
                    if ((j * (u[i] - u[i2])) % (p - 1) == 1)
                    {
                        x = j * (v[i2] - v[i]);
                        break;
                    }
                }
            }*/
            return x;
            /*decimal n = p - 1,
                a0 = 0, a1 = 0, b0 = 0, b1 = 0, x0 = 1, x1 = 1,
                cmp = p/3;//Phi(P)
            if (a == q)
            {
                return 1;
            }
            bool start = true;
            while(x0 != x1 || start)
            {
                start = false;
                if(x0 < cmp)
                {
                    x0 = (a * x0) % p;
                    //a0=a0
                    b0 = (b0 + 1) % p;
                }
                if(x0 >= cmp && x0< 2 * cmp)
                {
                    x0 = (x0 * x0) % p;
                    a0 = (2 * a0) % p;
                    b0 = (2 * b0) % p;
                }
                if (x0 >= 2 * cmp)
                {
                    x0 = (q * x0) % p;
                    a0 = (a0 + 1) % p;
                    //b0=b0
                }
                for (int f = 0; f < 2; f++)
                {
                    if (x1 < cmp)
                    {
                        x1 = (a * x1) % p;
                        //a1=a1
                        b1 = (b1 + 1) % p;
                    }
                    if (x1 >= cmp && x1 < 2 * cmp)
                    {
                        x1 = (x1 * x1) % p;
                        a1 = (2 * a1) % p;
                        b1 = (2 * b1) % p;
                    }
                    if (x1 >= 2 * cmp)
                    {
                        x1 = (q * x1) % p;
                        a1 = (a1 + 1) % p;
                        //b1=b1
                    }
                }
            }
            decimal u = (a0 - a1) % n,
                v = (b1 - b0) % n;
            if (v % n == 0)
            {
                return null;
            }
            //long d = (long)EuclideanAlgorithm(n, v);
            long d = (long)EuclideanAlgorithm(p, v);
            long nu = d;
            decimal x=0;
            short i = 0, w;
            while (i != (d + 1))
            {
                w = i;
                x = ((u * nu + w * n) / d) % n;
                if ((PowMod(q, x, p) - a % p) == 0)
                {
                    return x;
                }
                i++;
            }
            return x;*/
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
