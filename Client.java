import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
            System.err.println("Usage: java Client <hostname> <port> <userid>");
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

        //Receives servers response + signature
        byte[] encryptedServerBytes = new byte[dis.readInt()];
        dis.readFully(encryptedServerBytes);
        byte[] serverSignatureBytes = new byte[dis.readInt()];
        dis.readFully(serverSignatureBytes);

        //verifying the server's signature using its public key
        signature.initVerify(serverPublicKey);
        signature.update(encryptedServerBytes);
        if (!signature.verify(serverSignatureBytes)) {
            System.err.println("Server signature could not be verified");
            s.close();
            return;
        }

        //decrypts the server combined bytes using the client's private key
        cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
        byte[] serverCombinedData = cipher.doFinal(encryptedServerBytes);


        byte[]recievedClientRandBytes = Arrays.copyOfRange(serverCombinedData, 0, 16);

        if (!Arrays.equals(clientRandBytes, recievedClientRandBytes)) {
            System.err.println(" Random bytes do not match the server's bytes");
            s.close();
            return;
        }

        //using message digest to generate AES key and Initialisation vector for use with MD5 encryption
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] aesKeyBytes = md.digest(serverCombinedData);
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        byte [] initVectorBytes = md.digest(aesKeyBytes);
        IvParameterSpec iv = new IvParameterSpec(initVectorBytes);

        //using AES encryption for file transmission
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);

        //Getting the user command as input from command line
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        //repeatedly prompting the user to type in what they want to do
        while(true) {
            System.out.print("Enter command, options are: (ls/get filename/bye): ");
            String command = br.readLine();

            byte[] encryptedCommand = aesCipher.doFinal(command.getBytes());
            dos.writeInt(encryptedCommand.length);
            dos.write(encryptedCommand);

            //client connection ends if the command is "bye"
            if (command.equals("bye")) {
                s.close();
                break;
            }

            byte [] encryptedResponse = new byte[dis.readInt()];
            dis.readFully(encryptedResponse);
            byte[] decryptedResponse = aesCipher.doFinal(encryptedResponse);
            String response = new String(decryptedResponse);
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