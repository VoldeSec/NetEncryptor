using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;

namespace NetEncryptor
{
    internal class Program
    {
        public static void printHelp()
        {
            Console.WriteLine("");
            Console.WriteLine("Usage:\n");
            Console.WriteLine("\tNetEncryptor.exe -file <CSharp binary>\n");
            Console.WriteLine("Options:");
            Console.WriteLine("\t-mode string");
            Console.WriteLine("\t\t[*] cs - Encrypt CSharp binary and output HEX to new text file.");
            Console.WriteLine("\t\t[*] bin - Encrypt raw shellcode file binary and output to new bin file.");
            Console.WriteLine("\t\t[*] string - Encrypt string and output to current console.");
            Console.WriteLine("\t-en string");
            Console.WriteLine("\t\t[*] AES - AES encryption.");
            Console.WriteLine("\t\t[*] XOR - XOR encryption.");
            Console.WriteLine("\t-file string");
            Console.WriteLine("\t\tThe file/path to a CSharp binary/raw shellcode.");
            Console.WriteLine("\t-key string");
            Console.WriteLine("\t\tThe key for AES/XOR encryption.");
            Console.WriteLine("\t-salt string");
            Console.WriteLine("\t\tThe salt for AES encryption only.");
            Console.WriteLine("\t-iv string");
            Console.WriteLine("\t\tThe iv for AES encryption only.");
            Console.WriteLine("\t-random");
            Console.WriteLine("\t\tRandom the key, salt and iv.");
            Console.WriteLine("\t-s string");
            Console.WriteLine("\t\tString to encrypt in string mode.");
        }
        public static void Main(string[] args)
        {
            String key = "Passw0rd";
            String iv = "iv";
            String salt = "salt";
            string mode = "cs";
            string encryption = "aes";
            String filepath = "";
            String str = "";
            if (args.Length > 0)
            {

                foreach (string argument in args)
                {

                    if (argument.ToLower() == "--mode" || argument.ToLower() == "-mode")
                    {
                        int argData = Array.IndexOf(args, argument) + 1;
                        if (argData < args.Length)
                        {
                            mode = args[argData];
                            string[] modelist = { "cs", "bin", "string" };
                            if (!modelist.Contains(mode))
                            {
                                Console.WriteLine("[-] Please input valid mode");
                                return;
                            }
                        }
                    }

                    if (argument.ToLower() == "--en" || argument.ToLower() == "-en")
                    {
                        int argData = Array.IndexOf(args, argument) + 1;
                        if (argData < args.Length)
                        {
                            encryption = args[argData].ToLower();
                            string[] encryptlist = { "xor", "aes" };
                            if (!encryptlist.Contains(encryption))
                            {
                                Console.WriteLine("[-] Please input supported encryption");
                                return;
                            }
                        }
                    }

                    if (argument.ToLower() == "--key" || argument.ToLower() == "-key")
                    {
                        int argData = Array.IndexOf(args, argument) + 1;
                        if (argData < args.Length)
                        {
                            key = args[argData];
                        }
                    }
                    if (argument.ToLower() == "--salt" || argument.ToLower() == "-salt")
                    {
                        int argData = Array.IndexOf(args, argument) + 1;
                        if (argData < args.Length)
                        {
                            salt = args[argData];
                        }
                    }
                    if (argument.ToLower() == "--iv" || argument.ToLower() == "-iv")
                    {
                        int argData = Array.IndexOf(args, argument) + 1;
                        if (argData < args.Length)
                        {
                            iv = args[argData];
                        }
                    }

                    if (argument.ToLower() == "--file" || argument.ToLower() == "-file")
                    {
                        int argData = Array.IndexOf(args, argument) + 1;
                        if (argData < args.Length)
                        {
                            filepath = args[argData];
                        }
                    }

                    if (argument.ToLower() == "--random" || argument.ToLower() == "-random")
                    {
                        key = RandomString(8);
                        iv = RandomString(8);
                        salt = RandomString(8);
                    }


                    if (argument.ToLower() == "--s" || argument.ToLower() == "-s")
                    {
                        int argData = Array.IndexOf(args, argument) + 1;
                        if (argData < args.Length)
                        {
                            str = args[argData];
                        }
                    }

                    if (argument.ToLower() == "--h" || argument.ToLower() == "-h" || argument.ToLower() == "--help" || argument.ToLower() == "-help")
                    {
                        printHelp();
                        return;
                    }
                }

                if (encryption == "aes")
                {
                    Console.WriteLine("[+] Key for AES encryption: " + key);
                    Console.WriteLine("[+] Salt for AES encryption: " + salt);
                    Console.WriteLine("[+] IV for AES encryption: " + iv);
                    if (filepath.EndsWith("bin") && mode == "bin")
                    {
                        try
                        {
                            byte[] rawshellcode = System.IO.File.ReadAllBytes(filepath);
                            Console.WriteLine("[+] AES encrypting...");
                            byte[] encrypted = AESencrypt(rawshellcode, key, salt, iv);
                            outputfile(mode, encrypted, filepath);
                        }
                        catch
                        {
                            Console.WriteLine("[-] Something went wrong. Please ensure the file is valid .bin file");
                            return;
                        }
                    }

                    else if (filepath.EndsWith("exe") && mode == "cs")
                    {
                        try
                        {

                            string lines = readLocalFilePath(filepath, FileMode.Open);
                            byte[] buf = Convert.FromBase64CharArray(lines.ToCharArray(), 0, lines.Length);
                            Console.WriteLine("[+] AES encrypting...");
                            byte[] encrypted = AESencrypt(buf, key, salt, iv);
                            outputfile(mode, encrypted, filepath);
                        }

                        catch
                        {
                            Console.WriteLine("[-] Something went wrong. Please ensure the file is valid CSharp executable");
                            return;
                        }
                    }

                    else if (mode == "string")
                    {
                        if (str != "")
                        {
                            Console.WriteLine("[+] AES encrypting string: " + str);
                            byte[] encrypted = AESencrypt(Encoding.ASCII.GetBytes(str), key, salt, iv);
                            Console.WriteLine("[+] Encrypted String: ");
                            ByteArrayToString(encrypted, str);
                        }
                        else
                        {
                            Console.WriteLine("[-] Please input string using argument -s");
                            return;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] Please provide valid input. Check the help manuel!");
                    }

                }

                else if (encryption == "xor")
                {
                    Console.WriteLine("[+] Key for XOR encryption: " + key);
                    if (filepath.EndsWith("bin") && mode == "bin")
                    {
                        try
                        {
                            byte[] rawshellcode = System.IO.File.ReadAllBytes(filepath);
                            Console.WriteLine("[+] XOR encrypting...");
                            byte[] encrypted = XORencrypt(rawshellcode, key);
                            outputfile(mode, encrypted, filepath);
                        }
                        catch
                        {
                            Console.WriteLine("[-] Something went wrong. Please ensure the file is valid .bin file");
                            return;
                        }
                    }

                    else if (filepath.EndsWith("exe") && mode == "cs")
                    {
                        try
                        {
                            string lines = readLocalFilePath(filepath, FileMode.Open);
                            byte[] buf = Convert.FromBase64CharArray(lines.ToCharArray(), 0, lines.Length);
                            Console.WriteLine("[+] XOR encrypting...");
                            byte[] encrypted = XORencrypt(buf, key);
                            outputfile(mode, encrypted, filepath);
                        }

                        catch
                        {
                            Console.WriteLine("[-] Something went wrong. Please ensure the file is valid CSharp executable");
                            return;
                        }
                    }

                    else if (mode == "string")
                    {
                        Console.WriteLine("[+] XOR encrypting string: " + str);
                        byte[] encrypted = XORencrypt(Encoding.ASCII.GetBytes(str), key);
                        Console.WriteLine("[+] Encrypted String: ");
                        ByteArrayToString(encrypted, str);
                    }
                    else
                    {
                        Console.WriteLine("[-] Please provide valid input. Check the help manuel!");
                    }
                }
            }
            else
            {
                printHelp();
            }
        }
        private static byte[] AESencrypt(byte[] buf, string aeskey, string salt, string iv)
        {
            // Convert the password into bytes and then SHA-256 hash
            byte[] aeskeyBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(aeskey));

            // Convert the salt into bytes and then SHA-256 hash
            byte[] saltBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(salt));

            // Convert the iv into bytes and then MD5 hash (16 byte IV required for C++s)
            byte[] ivBytes = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(iv));
            Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.KeySize = 256;
            encryptor.BlockSize = 128;
            encryptor.Padding = PaddingMode.Zeros;
            encryptor.Key = CreateKey(aeskeyBytes, saltBytes);
            encryptor.IV = CreateKey(ivBytes, saltBytes, 16);

            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform aesEncryptor = encryptor.CreateEncryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);
            cryptoStream.Write(buf, 0, buf.Length);
            cryptoStream.FlushFinalBlock();
            byte[] encrypted = memoryStream.ToArray();
            return encrypted;
        }

        private static byte[] CreateKey(byte[] password, byte[] salt, int keyBytes = 16)
        {
            const int Iterations = 300;
            var keyGenerator = new Rfc2898DeriveBytes(password, salt, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }


        public static byte[] XORencrypt(byte[] buf, string xorkey)
        {
            byte[] encrypted = new byte[buf.Length];
            char[] xorkeyBytes = xorkey.ToCharArray();
            for (int i = 0; i < buf.Length; i++)
            {
                encrypted[i] = (byte)(buf[i] ^ xorkeyBytes[i % xorkeyBytes.Length]);
            }
            return encrypted;
        }

        public static void outputfile(string mode, byte[] encrypted, string filepath)
        {
            //output file name
            string outputfile = Path.GetFileNameWithoutExtension(filepath);
            for (int i = 1; i <= outputfile.Length - 1; i += 1)
            {
                outputfile = outputfile.Insert(i, "-");
                i++;
            }
            string docPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            if (mode == "bin")
            {
                File.WriteAllBytes(Path.Combine(docPath, outputfile + "_enc.bin"), encrypted);
                Console.WriteLine("[+] Encrypted file output to " + docPath + "\\" + outputfile + "_enc.bin");
            }
            if (mode == "cs")
            {
                string hexString = BitConverter.ToString(encrypted);
                hexString = hexString.Replace("-", "");
                File.WriteAllText(Path.Combine(docPath, outputfile + "_enc.txt"), hexString);
                Console.WriteLine("[+] Encrypted file output to " + docPath + "\\" + outputfile + "_enc.txt");
            }
            return;
        }

        private static string readLocalFilePath(string filePath, FileMode fileMode)
        {
            byte[] buffer = null;

            using (FileStream fs = new FileStream(filePath, fileMode, FileAccess.Read))
            {
                buffer = new byte[fs.Length];
                fs.Read(buffer, 0, (int)fs.Length);
            }
            string base64String = Convert.ToBase64String(buffer, 0, buffer.Length);
            return base64String;
        }

        private static Random random = new Random();

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static void ByteArrayToString(byte[] ba, string str)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            int totalCount = ba.Length;
            for (int count = 0; count < totalCount; count++)
            {
                byte b = ba[count];

                if ((count + 1) == totalCount) // Dont append comma for last item
                {
                    hex.AppendFormat("0x{0:x2}", b);
                }
                else
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }
            }
            Console.WriteLine("byte[] " + str + $"_enc = new byte[{ba.Length}] {{\n{hex}\n}};");
        }

    }
}
