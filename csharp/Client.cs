using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Classes;

public class Client
{
    public Client()
    {
        _rsa = new RSA(rsaPrivateKey);
    }

	public void execute()
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
				// Console.WriteLine("Recieved Key: {0}", Encoding.ASCII.GetString(messageReceived, 0, byteRecv));
				string aesKey = _rsa.decrypt(Encoding.ASCII.GetString(messageReceived, 0, bytesRecieved));
				// Console.WriteLine("Decrypted Key: {0}", aesKey);

				// Receive initialization vector
				bytesRecieved = sender.Receive(messageReceived);
				// Console.WriteLine("Recieved IV: {0}", Encoding.ASCII.GetString(messageReceived, 0, byteRecv));
				string aesIV = _rsa.decrypt(Encoding.ASCII.GetString(messageReceived, 0, bytesRecieved));
				// Console.WriteLine("Decrypted IV: {0}", aesIV);

                initializeAES(aesKey, aesIV);

				Console.WriteLine();

                // Communication loop
				Thread readThread = new Thread(new ParameterizedThreadStart(readMessages));
				readThread.Start(sender);

				while (true) {
					string plaintext = "";

					while (plaintext == "") {
						plaintext = Console.ReadLine();
					}

					byte[] ciphertext = _aes.encrypt(plaintext);
					sender.Send(ciphertext);
				}
			} catch (ArgumentNullException ane) {
				Console.WriteLine("ArgumentNullException: {0}", ane.ToString());
			} catch (SocketException se) {	
				if (se.ErrorCode == 10054) {
					Console.WriteLine("Host closed connection.");
				} else {
					Console.WriteLine("SocketException: {0}", se.ToString());
				}
			} catch (Exception e) {
				Console.WriteLine("Unexpected exception: {0}", e.ToString());
			}
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
		}
	}

    private void initializeAES(string key, string iv)
    {
        _aes = new AES(key, iv);
    }

    private void readMessages(Object obj) {
		Socket sender = (Socket) obj;
		byte[] messageReceived = new byte[1024];

		while (true) {
			int bytesRecieved = sender.Receive(messageReceived);
			string received = Encoding.ASCII.GetString(messageReceived, 0, bytesRecieved);

			string message = _aes.decrypt(received);
			Console.WriteLine("[Server] {0}", message);
		}
	}

    private static RSAParameters rsaPrivateKey = new RSAParameters
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

	private RSA _rsa;
	private AES _aes;
}
