import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Server {
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
        if (args.length != 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }
        int port = Integer.parseInt(args[0]);
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Waiting incoming connection...");


        while(true) {
            Socket s = ss.accept();
            DataInputStream dis = new DataInputStream(s.getInputStream());
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());

            PrivateKey serverPrivateKey = loadPrivateKey("server");

            //reads the encrypted userid+ gen random bytes
            byte[] encryptedData = new byte[dis.readInt()];
            dis.readFully(encryptedData);

            //reads the signature
            byte[] signature = new byte[dis.readInt()];
            dis.readFully(signature);

            //decrypt the encrypted data using server's private key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            //obtains the clients userid and the 16 bytes
            String userid = new String(decryptedData, 0, decryptedData.length - 16);
            byte[] clientRandomBytes = Arrays.copyOfRange(decryptedData, decryptedData.length-16, decryptedData.length);

            PublicKey clientPublicKey = loadPublicKey(userid);

            //verifying the signature using the client's public key
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(clientPublicKey);
            sig.update(encryptedData);
            if (!sig.verify(signature)) {
                System.err.println("Signature verification failed");
                s.close();
                continue;
            }



            //generate random bytes
            byte[] serverRandBytes = new byte[16];
            new SecureRandom().nextBytes(serverRandBytes);
            byte[] combinedBytes = new byte[32];
            System.arraycopy(clientRandomBytes, 0, combinedBytes, 0, 16);
            System.arraycopy(serverRandBytes, 0, combinedBytes, 16, 16);

            //encrypting the combined bytes using RSA
            cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
            byte[] encryptedCombinedBytes = cipher.doFinal(combinedBytes);

            //generates a signature of encrypted bytes
            sig.initSign(serverPrivateKey);
            sig.update(encryptedCombinedBytes);
            byte[] serverSignatureBytes = sig.sign();

            //sending the client the combined bytes and a signature using its private key
            dos.writeInt(encryptedCombinedBytes.length);
            dos.write(encryptedCombinedBytes);
            dos.writeInt(serverSignatureBytes.length);
            dos.write(serverSignatureBytes);




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
}
