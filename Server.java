import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.security.SecureRandom;

public class Server {
    public static void main(String [] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: java Server <port>");
            System.exit(1);
        }
        int port = Integer.parseInt(args[0]);
        String serverId = "server";
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Waiting incoming connection...");




        //server generating its own 16 fresh random bytes
        byte[] serverRandBytes = new byte[16];
        new SecureRandom().nextBytes(serverRandBytes);


        //encrypt combined bytes with RSA
        //encrypt the server's priv key and client pub key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Cipher.init(Cipher.ENCRYPT_MODE,);
        byte[] raw = cipher.doFinal();


        while(true) {
            Socket s = ss.accept();
            DataInputStream dis = new DataInputStream(s.getInputStream());
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());

            String x = null;

            try {
                while ((x = dis.readUTF()) != null) {

                    System.out.println(x);

                }
            }
            catch(IOException e) {
                System.err.println("Client closed its connection.");
            }
        }
    }
}
