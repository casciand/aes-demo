using System.Security.Cryptography;

class AesSystem
{
    const string FILE_PATH = @"C:\Users\acasc\Documents\research\aesDemo\message.txt";
    
    public static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            System.Console.WriteLine("Expected [1] argument, got [{0}].", args.Length);
            return 1;
        } else if (args[0] != "encrypt" && args[0] != "decrypt" && args[0] != "1" && args[0] != "2")
        {
            System.Console.WriteLine("Please enter either:\n(1) encrypt\n(2) decrypt");
            return 1;
        }

        if (args[0] == "1" || args[0] == "encrypt")
        {
            string plaintext = "";

            while (plaintext == "") {
                System.Console.Write("Enter a message to encrypt: ");
                plaintext = Console.ReadLine();
            }

            EncryptStringToBytes_Aes(plaintext);
        } else {
            string recovered = DecryptStringFromBytes_Aes();
            Console.WriteLine("Recovered plaintext: {0}", recovered);
        }

        return 0;
    }

    static void EncryptStringToBytes_Aes(string plainText)
    {
        byte[] ciphertext;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }

                    ciphertext = msEncrypt.ToArray();
                }
            }

            System.IO.File.WriteAllText(FILE_PATH, string.Empty);

            using (StreamWriter sw = File.AppendText(FILE_PATH))
            {
                sw.WriteLine(System.Convert.ToHexString(aesAlg.Key));
                sw.WriteLine(System.Convert.ToHexString(aesAlg.IV));
                sw.WriteLine(System.Convert.ToHexString(ciphertext));
            }
        }
    }

    static string DecryptStringFromBytes_Aes()
    {
        string plaintext = null;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            string[] contents = System.IO.File.ReadAllLines(FILE_PATH);

            aesAlg.Key = System.Convert.FromHexString(contents[0]);
            aesAlg.IV = System.Convert.FromHexString(contents[1]);
            byte[] ciphertext = System.Convert.FromHexString(contents[2]);

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return plaintext;
    }
}
