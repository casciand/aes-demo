using System;
using System.Security.Cryptography;
using System.Text;

class Program
{

    const string FILE_PATH = @"..\message.txt";

    static RSAParameters privateKey = new RSAParameters
    {
        D = System.Convert.FromHexString("519EEC38F331537D9DEA83B91E1A50159CAC006E825A5107F747BFBAB38CA8226E6808248900F61E5640DF52AEE3BEE3258834194CD63FF2D7D70EABFC5CBD31"),
        DP = System.Convert.FromHexString("3EF76D8CE01B2EDDFA618F509EDC88CF4D30F2F904FF5AF4699185E6FFFF7E8B"),
        DQ = System.Convert.FromHexString("9EE81FABEAE7C5E03E82AAD6298245FF3C97F8A40284A75B1A9A70DABBC98071"),
        Exponent = System.Convert.FromHexString("010001"),
        InverseQ = System.Convert.FromHexString("0BF7CFD35E66522729520AC5D6C249C715228E2CEAE476EC9D1B29DDCD9ECBA7"),
        Modulus = System.Convert.FromHexString("9BA04B03B8380EE352323DB2235BC6529E34B5B03D1440F67FAF6055B4900A5DE73ECDD1682260DEA537DBE3D1268468319C348E069456F9A883EA1A17FB0D35"),
        P = System.Convert.FromHexString("C25E529990839011AAF03C9AD952005C1908FC2D62A65344C5ACEA4419FA8217"),
        Q = System.Convert.FromHexString("CCF9199DC7E8B49F7BA424B9AEF10B030944597701C6E4632B4771BC964AB693"),       
    };

    static RSAParameters publicKey = new RSAParameters
    {
        Exponent = System.Convert.FromHexString("010001"),
        Modulus = System.Convert.FromHexString("C98D2988771B0C1BFDBDA9147026A4B3856E249224DB027FA45BB1F9931E54D165DC63867BA20F67CBAD46C9685849721EE7A74E237C0E0598EA5FA704EA8165"),
    };
    
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

        UnicodeEncoding ByteConverter = new UnicodeEncoding();

        if (args[0] == "1" || args[0] == "encrypt")
        {
            string plaintext = "";

            while (plaintext == "") {
                System.Console.Write("Enter a message to encrypt: ");
                plaintext = Console.ReadLine();
            }

            RSAEncrypt(ByteConverter.GetBytes(plaintext), Program.publicKey);
        } else {
            byte[] recovered = RSADecrypt(Program.privateKey);
            Console.WriteLine("Recovered plaintext: {0}", Encoding.UTF8.GetString(recovered));
        }

        return 0;
    }

    public static void RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo)
    {
        try
        {
            byte[] encryptedData;

            // Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {

                // Import the RSA Key information. This only needs
                // to include the public key information.
                RSA.ImportParameters(RSAKeyInfo);

                // Encrypt the passed byte array and specify OAEP padding.  
                // OAEP padding is only available on Microsoft Windows XP or
                // later.  
                encryptedData = RSA.Encrypt(DataToEncrypt, true);
            }

            System.IO.File.WriteAllText(FILE_PATH, string.Empty);

            using (StreamWriter sw = File.AppendText(FILE_PATH))
            {
                sw.WriteLine(System.Convert.ToHexString(encryptedData));
            }
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
        }
    }

    public static byte[] RSADecrypt(RSAParameters RSAKeyInfo)
    {
        string[] contents = System.IO.File.ReadAllLines(FILE_PATH);

        try
        {
            byte[] plaintext;
            byte[] ciphertext = System.Convert.FromHexString(contents[0]);

            // Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                // Import the RSA Key information. This needs
                // to include the private key information.
                RSA.ImportParameters(RSAKeyInfo);

                // Decrypt the passed byte array and specify OAEP padding.  
                // OAEP padding is only available on Microsoft Windows XP or
                // later.  
                //Console.WriteLine(System.Convert.ToHexString(ciphertext));
                plaintext = RSA.Decrypt(ciphertext, true);
            }

            return plaintext;
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
