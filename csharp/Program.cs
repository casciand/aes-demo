using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Client {
	static RSAParameters privateKey = new RSAParameters
    {
        D = System.Convert.FromHexString("08407F1C1FD0E0F484A771318F3E1BF97209E3BDCA50FAC55445D4E166963B0F1328C93B1298BEEB44B54441E48468484B7C516517C22A9DC915E6015ED9642E9502B3A14054E7394DF2DD2D17DDC4E81D099686ADB33313D06B58CA4643DB2FC385E03F3D8DB7910A2BBE02975FADF5BD308FD22B464B7FF153BF255DF3C769"),
        DP = System.Convert.FromHexString("EE3FC90F715FB3CB8EDFC93694F876FA8DC4C006C9EE86DB19C188987DC9DDCDE2296BE0FD8E4909038A34AF2544CB016E1BED2D6C52CB34C34C8710BC90EA31"),
        DQ = System.Convert.FromHexString("138278242E6D00F3C3696E97550B4AA49F11F07644CC01452AA0C0792E898466D9CCAA8716BCA03BD04DF911F08195A9D04F6456E217558BB9D9AEF52F2E62C9"),
        Exponent = System.Convert.FromHexString("010001"),
        InverseQ = System.Convert.FromHexString("2A9786C0880E08743CA576930210D35600530974452AF21982126B8C87D10BA748058BB4AEC67775B8272C3CAF430DCAE36B048F67428C48343F05C776DE2AF7"),
        Modulus = System.Convert.FromHexString("DEEBE218CA49F2A3F138F773E92C06B4DE5F94C11D34AA58F5FE02DFA752455C762BF05E1BD6CB73674228DAB9F6CC5E1A3C07BF1E860DEC8D5E3DF87E135069D3C8BFC5297F821D19C70953E99B6363DACEF8367400E068035CF2DAB8A4FCFC8EA96C89F3F9F5AA5D3E584AECE64F0C1C8B853305E42F6C74971F4B6AB01BE1"),
        P = System.Convert.FromHexString("EE570F78ADBF6F1DAD739AECE464755E058FD34758A5A050A82C6683A2B99CFE77D289C7541F298330DFCD3496E215783C630491C72AE38CE3B6A37C974FD63F"),
        Q = System.Convert.FromHexString("EF705AD466D7200F8CCF3278375A4DD9BAE5B4D7060DB6CDC100B9554930A7FFE9ECA5DC64A9154E74AD08A000EF9CD4C1BC56F9FAEDC3EF189CE60EDE3AC5DF"),       
    };

	public static string RSADecrypt(string message)
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
                RSA.ImportParameters(privateKey);

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

	static byte[] AESEncrypt(string plaintext, string key, string iv)
    {
        byte[] ciphertext;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(System.Convert.FromHexString(key), System.Convert.FromHexString(iv));

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

	static void executeClient()
	{
		try {
			// Establish the remote endpoint for the socket
			IPHostEntry ipHost = Dns.GetHostEntry("localhost");
			IPAddress ipAddr = ipHost.AddressList[1];
			IPEndPoint localEndPoint = new IPEndPoint(ipAddr, 8080);

			// Create TCP/IP Socket
			Socket sender = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

			try {
				// Connect socket to the remote endpoint
				sender.Connect(localEndPoint);
				Console.WriteLine("Socket connected to -> {0} ", sender.RemoteEndPoint.ToString());

				// Send public key to server
				byte[] modulus = Encoding.ASCII.GetBytes("0xDEEBE218CA49F2A3F138F773E92C06B4DE5F94C11D34AA58F5FE02DFA752455C762BF05E1BD6CB73674228DAB9F6CC5E1A3C07BF1E860DEC8D5E3DF87E135069D3C8BFC5297F821D19C70953E99B6363DACEF8367400E068035CF2DAB8A4FCFC8EA96C89F3F9F5AA5D3E584AECE64F0C1C8B853305E42F6C74971F4B6AB01BE1");
				sender.Send(modulus);

				byte[] exponent = Encoding.ASCII.GetBytes("0x10001");
				sender.Send(exponent);

				// Data buffer
				byte[] messageReceived = new byte[1024];

				// Receive symmetric key
				int bytesRecieved = sender.Receive(messageReceived);
				// Console.WriteLine("Recieved Key -> {0}", Encoding.ASCII.GetString(messageReceived, 0, byteRecv));
				string key = RSADecrypt(Encoding.ASCII.GetString(messageReceived, 0, bytesRecieved));
				// Console.WriteLine("Decrypted Key -> {0}", key);

				// Receive initialization vector
				bytesRecieved = sender.Receive(messageReceived);
				// Console.WriteLine("Recieved IV -> {0}", Encoding.ASCII.GetString(messageReceived, 0, byteRecv));
				string iv = RSADecrypt(Encoding.ASCII.GetString(messageReceived, 0, bytesRecieved));
				// Console.WriteLine("Decrypted IV -> {0}", iv);

				Console.WriteLine();

				// Indefinitely send messages to the server
				while (true) {
					string plaintext = "";

					while (plaintext == "") {
						Console.Write("-> ");
						plaintext = Console.ReadLine();
					}

					byte[] ciphertext = AESEncrypt(plaintext, key, iv);
					sender.Send(ciphertext);
				}
			} catch (ArgumentNullException ane) {
				Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
			} catch (SocketException se) {	
				if (se.ErrorCode == 10054) {
					Console.WriteLine("Host closed connection.");
				} else {
					Console.WriteLine("SocketException : {0}", se.ToString());
				}
			} catch (Exception e) {
				Console.WriteLine("Unexpected exception : {0}", e.ToString());
			}
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
		}
	}

	static void Main(string[] args)
	{
		executeClient();
	}
}
