using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Classes;

public class Client
{
	const int ENCRYPTED_KEY_SIZE = 256;
	const int BUFFER_SIZE = 2048;

    public Client()
    {
        _rsa = new RSA();
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
				string modulus = _rsa.getModulus();
				sender.Send(Encoding.ASCII.GetBytes(modulus));
				// sender.NoDelay = true;

				string exponent = _rsa.getExponent();
				sender.Send(Encoding.ASCII.GetBytes(exponent));

				// Data buffer
				byte[] messageReceived = new byte[BUFFER_SIZE];

				// Receive symmetric key
				int bytesRecieved = 0;
				string hexRecieved = "";

				while (bytesRecieved < 2 * ENCRYPTED_KEY_SIZE) {
					bytesRecieved += sender.Receive(messageReceived);
					hexRecieved += Encoding.ASCII.GetString(messageReceived, 0, bytesRecieved);
				}
				
				// Console.WriteLine("Recieved Key: {0}", hexRecieved.Substring(0, 256));
				string aesKey = _rsa.decrypt(hexRecieved.Substring(0, ENCRYPTED_KEY_SIZE));
				// Console.WriteLine("Decrypted Key: {0}", aesKey);

				// Receive initialization vector
				// Console.WriteLine("Recieved IV: {0}", hexRecieved.Substring(256));
				string aesIV = _rsa.decrypt(hexRecieved.Substring(ENCRYPTED_KEY_SIZE));
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
		byte[] messageReceived = new byte[BUFFER_SIZE];

		while (true) {
			int bytesRecieved = sender.Receive(messageReceived);
			string received = Encoding.ASCII.GetString(messageReceived, 0, bytesRecieved);

			string message = _aes.decrypt(received);
			Console.WriteLine("[Server] {0}", message);
		}
	}

	private RSA _rsa;
	private AES _aes;
}
