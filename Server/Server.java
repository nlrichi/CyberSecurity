package Server;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Server {
    private static PublicKey loadPublicKey(String userid) throws Exception {
        File pubFile = new File(userid + ".pub");
        byte[] pubKeyBytes = Files.readAllBytes(pubFile.toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(pubSpec);
    }

    private static PrivateKey loadPrivateKey(String userid) throws Exception {
        File privFile = new File(userid + ".prv");
        byte[] privKeyBytes = Files.readAllBytes(privFile.toPath());
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(privSpec);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }
        int port = Integer.parseInt(args[0]);
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Waiting incoming connection...");

        while (true) {
            Socket s = ss.accept();
            DataInputStream dis = new DataInputStream(s.getInputStream());
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());

            PrivateKey serverPrivateKey = loadPrivateKey("server");

            // Reads the encrypted userid + gen random bytes
            byte[] encryptedData = new byte[dis.readInt()];
            dis.readFully(encryptedData);

            // Reads the signature
            byte[] signature = new byte[dis.readInt()];
            dis.readFully(signature);

            // Decrypt the encrypted data using server's private key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            // Obtains the client's userid and the 16 bytes
            String userid = new String(decryptedData, 0, decryptedData.length - 16);
            byte[] clientRandomBytes = Arrays.copyOfRange(decryptedData, decryptedData.length - 16, decryptedData.length);

            // Log client userid and 32 plaintext bytes
            System.out.println("Client userid: " + userid);
            System.out.println("32 plaintext bytes: " + Base64.getEncoder().encodeToString(decryptedData));

            PublicKey clientPublicKey = loadPublicKey(userid);

            // Verifying the signature using the client's public key
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(clientPublicKey);
            sig.update(encryptedData);
            if (!sig.verify(signature)) {
                System.err.println("Signature verification failed for user: " + userid);
                s.close();
                continue;
            }

            // Generate random bytes
            byte[] serverRandBytes = new byte[16];
            new SecureRandom().nextBytes(serverRandBytes);
            byte[] combinedBytes = new byte[32];
            System.arraycopy(clientRandomBytes, 0, combinedBytes, 0, 16);
            System.arraycopy(serverRandBytes, 0, combinedBytes, 16, 16);

            // Encrypting the combined bytes using RSA
            cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
            byte[] encryptedCombinedBytes = cipher.doFinal(combinedBytes);

            // Generates a signature of encrypted bytes
            sig.initSign(serverPrivateKey);
            sig.update(encryptedCombinedBytes);
            byte[] serverSignatureBytes = sig.sign();

            // Sending the client the combined bytes and a signature using its private key
            dos.writeInt(encryptedCombinedBytes.length);
            dos.write(encryptedCombinedBytes);
            dos.writeInt(serverSignatureBytes.length);
            dos.write(serverSignatureBytes);

            // Using message digest to generate AES key and Initialisation vector for use with MD5 encryption
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] aesKeyBytes = md.digest(combinedBytes);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            byte[] initVectorBytes = md.digest(aesKeyBytes);
            IvParameterSpec iv = new IvParameterSpec(initVectorBytes);

            // Using AES encryption for file transmission
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);

            while (true) {
                // Gets encrypted client's command and decrypts it
                byte[] encryptedCommand = new byte[dis.readInt()];
                dis.readFully(encryptedCommand);
                byte[] decryptedCommand = aesCipher.doFinal(encryptedCommand);
                String command = new String(decryptedCommand);

                if (command.equals("ls")) {
                    System.out.println("List of files");
                    File dir = new File("."); // Current directory
                    File[] files = dir.listFiles((d, name) -> !name.endsWith(".prv")); // Exclude .prv files

                    if (files == null || files.length == 0) {
                        System.out.println("No files available for download.");
                        byte[] encryptedResponse = aesCipher.doFinal("No files available for download.".getBytes());
                        dos.writeInt(encryptedResponse.length);
                        dos.write(encryptedResponse);
                    } else {
                        StringBuilder filesList = new StringBuilder();
                        for (File file : files) {
                            filesList.append(file.getName()).append("\n");
                        }
                        byte[] encryptedFileList = aesCipher.doFinal(filesList.toString().getBytes());
                        dos.writeInt(encryptedFileList.length);
                        dos.write(encryptedFileList);
                    }
                } else if (command.startsWith("get")) {
                    System.out.println("Getting file...");
                    String fileName = command.split(" ")[1];
                    File file = new File(fileName);
                    if (!file.exists() || file.isDirectory() || fileName.endsWith(".prv")) {
                        byte[] encryptedResponse = aesCipher.doFinal("File not found".getBytes());
                        dos.writeInt(encryptedResponse.length);
                        dos.write(encryptedResponse);
                    } else {
                        byte[] fileContent = Files.readAllBytes(file.toPath());
                        byte[] encryptedResponse = aesCipher.doFinal(fileContent);
                        dos.writeInt(encryptedResponse.length);
                        dos.write(encryptedResponse);
                    }
                } else if (command.equals("bye")) {
                    s.close();
                    break;
                }
            }
        }
    }
}
