using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO.Compression;

namespace PasswordCracker
{
    /// <summary>
    /// A list of md5 hashed passwords is contained within the passwords_hashed.txt file.  Your task
    /// is to crack each of the passwords.  Your input will be an array of strings obtained by reading
    /// in each line of the text file and your output will be validated by passing an array of the
    /// cracked passwords to the Validator.ValidateResults() method.  This method will compute a SHA256
    /// hash of each of your solved passwords and compare it against a list of known hashes for each
    /// password.  If they match, it means that you correctly cracked the password.  Be warned that the
    /// test is ALL or NOTHING.. so one wrong password means the test fails.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            // Define the alphabet
            IEnumerable<char> alphabet = "abcdefghijklmnopqrstuvwxyz".ToCharArray();

            // Preset list of MD5 hashes
            HashSet<string> hashedPasswords = File.ReadAllLines("passwords_hashed.txt").ToHashSet();

            List<string> matchingStrings = new List<string>();

            IEnumerable<string> GenerateStrings(IEnumerable<char> alphabet)
            {
                foreach (var i in alphabet)
                    foreach (var j in alphabet)
                        foreach (var k in alphabet)
                            foreach (var l in alphabet)
                                foreach (var m in alphabet)
                                    yield return $"{i}{j}{k}{l}{m}";
            }

            var stringsGenerator = GenerateStrings(alphabet);

            foreach (string str in stringsGenerator)
            {
                string md5Hash = md5(str);

                if (hashedPasswords.Contains(md5Hash))
                {
                    matchingStrings.Add(str);
                    if (matchingStrings.Count == hashedPasswords.Count)
                    {
                        break;
                    }
                }
            };


            Console.WriteLine("MD5 Password Cracker v1.0");

            bool passwordsValidated = Validator.ValidateResults(matchingStrings.ToArray());

            sw.Stop();

            /*Console.WriteLine($"\nPasswords successfully cracked: {passwordsValidated}");*/
            Console.WriteLine(passwordsValidated);


            System.TimeSpan ts = sw.Elapsed;

            // Format and display the TimeSpan value
            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours, ts.Minutes, ts.Seconds,
                ts.Milliseconds / 10);
            Console.WriteLine("RunTime " + elapsedTime);
        }


        public static string md5(string input)
        {
            // Use input string to calculate MD5 hash
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }
    }
}