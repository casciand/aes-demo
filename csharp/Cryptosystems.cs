using System.Security.Cryptography;
using System.Text;

namespace Classes;

public class AES
{
    private string _key;
    private string _iv;

    public AES(string key, string iv)
    {
        _key = key;
        _iv = iv;
    }

    public byte[] encrypt(string plaintext)
    {
        byte[] ciphertext;

        // Create an Aes object with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = System.Convert.FromHexString(_key);
            aesAlg.IV = System.Convert.FromHexString(_iv);

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        // Write all data to the stream.
                        swEncrypt.Write(plaintext);
                    }

                    ciphertext = msEncrypt.ToArray();
                }
            }
        }

		return ciphertext;
    }

	public string decrypt(string message)
    {
        string plaintext = null;

        // Create an Aes object with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = System.Convert.FromHexString(_key);
            aesAlg.IV = System.Convert.FromHexString(_iv);
            byte[] ciphertext = System.Convert.FromHexString(message);

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

public class RSA
{
    private RSAParameters _key;

    public RSA(RSAParameters key)
    {
        _key = key;
    }

    public string decrypt(string message)
    {
        try
        {
            byte[] plaintext;
            byte[] ciphertext = System.Convert.FromHexString(message);

            // Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                // Import the RSA Key information. This needs
                // to include the private key information.
                RSA.ImportParameters(_key);

                // Decrypt the passed byte array and specify OAEP padding.  
                // OAEP padding is only available on Microsoft Windows XP or
                // later.  
                plaintext = RSA.Decrypt(ciphertext, true);
            }

            return Encoding.UTF8.GetString(plaintext);
        }
        // Catch and display a CryptographicException  
        // to the console.
        catch (CryptographicException e)
        {
            Console.WriteLine(e.ToString());
            return null;
        }
    }
}
