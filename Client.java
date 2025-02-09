import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
public class Client {
    private static PublicKey loadPublicKey(String userid) throws Exception {
        File pubFile = new File(userid+".pub");
        byte[] pubKeyBytes = Files.readAllBytes(pubFile.toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(pubSpec);

    }

    private static PrivateKey loadPrivateKey(String userid) throws Exception {
        File privFile = new File(userid+".priv");
        byte[] privKeyBytes = Files.readAllBytes(privFile.toPath());
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(privSpec);
    }

    public static void main(String [] args) throws Exception {
        //forces the required arguements to be passed.
        if (args.length != 3) {
            System.out.println("Usage: java Client <hostname> <port> <userid>");
        }

        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]);           // port of server
        String userid = args[2]; //userid of client

        //Connecting to the server via socket
        Socket s = new Socket(host, port);
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());
        DataInputStream dis = new DataInputStream(s.getInputStream());


        PrivateKey clientPrivateKey = loadPrivateKey(userid);
        PublicKey serverPublicKey = loadPublicKey("server");


        //generate 16 fresh random bytes
        byte[] clientRandBytes = new byte[16];
        new SecureRandom().nextBytes(clientRandBytes);

        //encrypt the client 16 bytes + userid using server's public key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedData = cipher.doFinal((userid + new String(clientRandBytes)).getBytes());


        //generate signature of encrypted bytes
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(clientPrivateKey);
        signature.update(encryptedData);
        byte[] signatureBytes = signature.sign();

        //send the encrypted data to the server
        dos.writeInt(encryptedData.length);
        dos.write(encryptedData);
        dos.writeInt(signatureBytes.length);
        dos.write(signatureBytes);


        //Getting the user command as input from command line
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        //repeatedly prompting the user to type in what they want to do
        while(true) {
            System.out.print("Enter command, options are: (ls/get filename/bye): ");
            String command = br.readLine();
            //client connection ends if the command is "bye"
            if (command.equals("bye")) {
                s.close();
                break;
            }

            if (command.startsWith("get")) {
                FileOutputStream fos = new FileOutputStream(command.split(" ")[1]);
                fos.write(decryptedResponse);
                fos.close();
            } else {
                System.out.println(response);
            }

        }


    }
}