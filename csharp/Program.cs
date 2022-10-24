using System;
using System.Security.Cryptography;
using System.Text;

class Program
{

    const string FILE_PATH = @"..\message.txt";

    static RSAParameters CSKeyInfo = new RSAParameters
    {
        D = System.Convert.FromHexString("02456706B11A878FE22E1EA9C2AC652291F36842588A3A4A494098BF0E293E355AB5E6698917679B50BD7A264B94AA3CCEDFD83DC66DFCDCCA1F88EE0E245B2416FB183BE5BC960F9C8FC8CDEF31143719222C37CB8F5038C5FD5E9A3560B4CB56DF0205EACC09B65BEB9F35986C698291EA872C286C3CA6A900DC5FF89702F9"),
        DP = System.Convert.FromHexString("E2DE2D3724D3F9032D796EBFA4C60370103AC64A2D6305B609E6BA665314BF8317CF1FDDF2B41904CFEC83929E99B3A468F3A4BE2A4CD44EF63518578D6A108D"),
        DQ = System.Convert.FromHexString("C4B7A228CE5A9DCF6682D02CB519D6855DDC64E1B9791EB37252627BA2498F9C212582C368BD476F116B6CF1848598E56F7C4608018D5D91092212B1688C4D41"),
        Exponent = System.Convert.FromHexString("010001"),
        InverseQ = System.Convert.FromHexString("0532FF7DA4E20466BFBE20BB08D5BC194BC53E0B1A594ACBBEE5643307CF0815D45D94075138458569035542D6BDEC21F6C96FC7B21B5EB3EE6C6BB634ABD4FD"),
        Modulus = System.Convert.FromHexString("D4064ECDB8F8384F67917276A428C60120153A41EEB4736C816A7BDC97CFFF7D0D95ECD4C9A45B6E41EE17418AECF883B002984B5DFFBDE9BFEF9BEE2843914F2D262056AA777DDA6E64D5905FC78C3901B49EE1137CC6518CC064F2DD139C1CD2C7D6AE1EE70530CD0262A356AFEDE90A6931845CE21FA09BB2B9337AEE8981"),
        P = System.Convert.FromHexString("F1D4AE11E12F1DFBFAD29FA535C74A264E46654D277C80B7680614971E99A7E0519EBF9B589F79211B3640A2B2A558A812278BF41AA931F92A479852D582C2AF"),
        Q = System.Convert.FromHexString("E0728D9F3C57C3B791B1CDB991ED82EB8DC540E20AF5694EF19F1CBA90EC65FF5C910F714A4EA7A1B2889F018107B09C58DBDEEE7DE2795C72528EB4889E42CF"),       
    };

    static RSAParameters CPPKeyInfo = new RSAParameters
    {
        D = System.Convert.FromHexString("430B5599002F9052B7ABA64D7732BA227F789728326384161D472DA9F38D3586E112917D69F15F093F8FEF8857CE0A348DF4028BDCDEE71A70F4A860A46F92C40150FB039956F389622BA37E5D8774AB06F7B68D1F41D8D066B63B0EB1B34AC011D58C0373B9C6470D2E4B8A0D2692E5C97C39000DBF2177056109A249FD85C5"),
        DP = System.Convert.FromHexString("82B7AB2CB75A6747F915639B034A7BF98BBFFB5D97CE91A07BA2747FEE98D311AECB23689F3D6E010B625B9F06A09653C5A84BCA3BEA3FB31C71A67FEDE67FBD"),
        DQ = System.Convert.FromHexString("64749F84996C6B7E13601FB690B131B4B3FD3C9F10A7FAAAB9D89DA1DECFCD65512EFFA9A539741D9DE52097582E5952CC5869316F0573E13EC0854DA7E0A0D9"),
        Exponent = System.Convert.FromHexString("010001"),
        InverseQ = System.Convert.FromHexString("D4DBA93BA31F02BFACC7C32B901F2BFBF18A81A97CFE91E341AA20DD21597AAA8E07568AFA3861457FCAA0F3CCC6D5B72FEF29EF0C0347450F4A5EC7B6D779C0"),
        Modulus = System.Convert.FromHexString("B9A37D00922650B06D866E0254B0A89C48D8799418A830FDE2504E9414F94073D81566599D26D9AA20F534F24F90BF991F1A0479F3FB277B44CA2F1B3061AE153EAD4DAB16E1C5A47EEE6159C6FF793FDBEA4AE47EABDE9D6134BC48B2BEE424C04A00717A94FACC15396EE4177B667B4F816315C60510B9C1E63918B6BDE259"),
        P = System.Convert.FromHexString("EF564809BEAE6A029B1F844D1EA2BF1A464D17B68E958B878A4516F24DF66D9DA14174F673139EAA0734797AE7020D64248878A14A6620DA14B7BE191EEDB02F"),
        Q = System.Convert.FromHexString("C690230840DD6AA9AB6CC479CF92514570E5A91021A811314B9985980416F2DA180FB21D60B901E073A6EB0097BF66D29CEAC3733B228529BEB9661ECCFF2BF7"),       
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

            RSAEncrypt(ByteConverter.GetBytes(plaintext), Program.CSKeyInfo);
        } else {
            byte[] recovered = RSADecrypt(Program.CSKeyInfo);
            Console.WriteLine("Recovered plaintext: {0}", ByteConverter.GetString(recovered));
        }

        return 0;
    }

    public static void RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo)
    {
        try
        {
            byte[] encryptedData;

            //Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {

                //Import the RSA Key information. This only needs
                //toinclude the public key information.
                RSA.ImportParameters(RSAKeyInfo);

                //Encrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later.  
                encryptedData = RSA.Encrypt(DataToEncrypt, false);
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
            //Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                //Import the RSA Key information. This needs
                //to include the private key information.
                RSA.ImportParameters(RSAKeyInfo);

                //Decrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later.  
                plaintext = RSA.Decrypt(ciphertext, false);
            }

            return plaintext;
        }
        //Catch and display a CryptographicException  
        //to the console.
        catch (CryptographicException e)
        {
            Console.WriteLine(e.ToString());
            return null;
        }
    }
}
