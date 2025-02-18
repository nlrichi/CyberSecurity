package client;

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

public class Client {
    private static PublicKey loadPublicKey(String userid) throws Exception {
        File pubFile = new File("client/server.pub");
        byte[] pubKeyBytes = Files.readAllBytes(pubFile.toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(pubSpec);
    }

    private static PrivateKey loadPrivateKey(String userid) throws Exception {
        File privFile = new File("client/" + userid + ".prv");
        byte[] privKeyBytes = Files.readAllBytes(privFile.toPath());
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(privSpec);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: java client <hostname> <port> <userid>");
            System.exit(1);
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userid = args[2];

        try {
            Socket s = new Socket(host, port);

            DataOutputStream dos = new DataOutputStream(s.getOutputStream());
            DataInputStream dis = new DataInputStream(s.getInputStream());

            PrivateKey clientPrivateKey = loadPrivateKey(userid);
            PublicKey serverPublicKey = loadPublicKey("server");

            byte[] clientRandBytes = new byte[16];
            new SecureRandom().nextBytes(clientRandBytes);

            byte[] useridBytes = userid.getBytes();
            byte[] combinedData = new byte[useridBytes.length + clientRandBytes.length];
            System.arraycopy(useridBytes, 0, combinedData, 0, useridBytes.length);
            System.arraycopy(clientRandBytes, 0, combinedData, useridBytes.length, clientRandBytes.length);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedData = cipher.doFinal(combinedData);

            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(clientPrivateKey);
            signature.update(encryptedData);
            byte[] signatureBytes = signature.sign();

            dos.writeInt(encryptedData.length);
            dos.write(encryptedData);
            dos.writeInt(signatureBytes.length);
            dos.write(signatureBytes);

            byte[] encryptedServerBytes = new byte[dis.readInt()];
            dis.readFully(encryptedServerBytes);
            byte[] serverSignatureBytes = new byte[dis.readInt()];
            dis.readFully(serverSignatureBytes);

            signature.initVerify(serverPublicKey);
            signature.update(encryptedServerBytes);
            if (!signature.verify(serverSignatureBytes)) {
                System.err.println("Server signature could not be verified");
                s.close();
                return;
            }

            cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
            byte[] serverCombinedData = cipher.doFinal(encryptedServerBytes);

            byte[] receivedClientRandBytes = Arrays.copyOfRange(serverCombinedData, 0, 16);
            if (!Arrays.equals(clientRandBytes, receivedClientRandBytes)) {
                System.err.println("Random bytes do not match the server's bytes");
                s.close();
                return;
            }

            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] aesKeyBytes = md.digest(serverCombinedData);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            byte[] initVectorBytes = md.digest(aesKeyBytes);
            IvParameterSpec iv = new IvParameterSpec(initVectorBytes);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

            while (true) {
                System.out.print("Enter command:");
                String command = br.readLine();

                if (!command.startsWith("ls") && !command.startsWith("get") && !command.equals("bye")) {
                    System.out.println("Unrecognized command. Please try again.");
                    continue;
                }

                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
                byte[] encryptedCommand = aesCipher.doFinal(command.getBytes());
                dos.writeInt(encryptedCommand.length);
                dos.write(encryptedCommand);

                if (command.equals("bye")) {
                    s.close();
                    break;
                }

                byte[] encryptedResponse = new byte[dis.readInt()];
                dis.readFully(encryptedResponse);
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
                byte[] decryptedResponse = aesCipher.doFinal(encryptedResponse);

                if (command.startsWith("get")) {
                    String fileName = command.split(" ")[1];
                    String response = new String(decryptedResponse);
                    if (response.startsWith("File not found") || response.startsWith("File not found or access denied")) {
                        System.out.println("Error: " + response);
                    } else {
                        try {
                            FileOutputStream fos = new FileOutputStream(fileName);
                            fos.write(decryptedResponse);
                            fos.close();
                        } catch (IOException e) {
                            System.err.println("Error saving file: " + e.getMessage());
                        }
                    }
                } else {
                    System.out.println("Server response:");
                    System.out.println(new String(decryptedResponse));
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}