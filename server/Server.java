package server;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Server {
    private static PublicKey loadPublicKey(String userid) throws Exception {
        if (userid.equals("server")) {
            File pubFile = new File("server/server.pub");
            byte[] pubKeyBytes = Files.readAllBytes(pubFile.toPath());
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(pubSpec);
        }
        File pubFile = new File("server/" + userid + ".pub");
        byte[] pubKeyBytes = Files.readAllBytes(pubFile.toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(pubSpec);
    }

    private static PrivateKey loadPrivateKey(String userid) throws Exception {
        File privFile = new File("server/server.prv");
        byte[] privKeyBytes = Files.readAllBytes(privFile.toPath());
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(privSpec);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java server <port>");
            System.exit(1);
        }
        int port = Integer.parseInt(args[0]);
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Waiting incoming connection...");

        while (true) {
            try {
                Socket s = ss.accept();
                DataInputStream dis = new DataInputStream(s.getInputStream());
                DataOutputStream dos = new DataOutputStream(s.getOutputStream());

                PrivateKey serverPrivateKey = loadPrivateKey("server");

                byte[] encryptedData = new byte[dis.readInt()];
                dis.readFully(encryptedData);

                byte[] signature = new byte[dis.readInt()];
                dis.readFully(signature);

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
                byte[] decryptedData = cipher.doFinal(encryptedData);

                int useridLength = decryptedData.length - 16;
                String userid = new String(decryptedData, 0, useridLength, StandardCharsets.UTF_8);
                byte[] clientRandomBytes = Arrays.copyOfRange(decryptedData, useridLength, decryptedData.length);

                System.out.println("client userid: " + userid);
                System.out.println("32 plaintext bytes: " + Base64.getEncoder().encodeToString(decryptedData));

                PublicKey clientPublicKey = loadPublicKey(userid);

                Signature sig = Signature.getInstance("SHA1withRSA");
                sig.initVerify(clientPublicKey);
                sig.update(encryptedData);
                if (!sig.verify(signature)) {
                    System.err.println("Signature verification failed for user: " + userid);
                    s.close();
                    continue;
                }

                byte[] serverRandBytes = new byte[16];
                new SecureRandom().nextBytes(serverRandBytes);
                byte[] combinedBytes = new byte[32];
                System.arraycopy(clientRandomBytes, 0, combinedBytes, 0, 16);
                System.arraycopy(serverRandBytes, 0, combinedBytes, 16, 16);

                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] encryptedCombinedBytes = cipher.doFinal(combinedBytes);

                sig.initSign(serverPrivateKey);
                sig.update(encryptedCombinedBytes);
                byte[] serverSignatureBytes = sig.sign();

                dos.writeInt(encryptedCombinedBytes.length);
                dos.write(encryptedCombinedBytes);
                dos.writeInt(serverSignatureBytes.length);
                dos.write(serverSignatureBytes);

                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] aesKeyBytes = md.digest(combinedBytes);
                SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
                byte[] initVectorBytes = md.digest(aesKeyBytes);
                IvParameterSpec iv = new IvParameterSpec(initVectorBytes);

                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);

                while (true) {
                    try {
                        byte[] encryptedCommand = new byte[dis.readInt()];
                        dis.readFully(encryptedCommand);
                        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
                        byte[] decryptedCommand = aesCipher.doFinal(encryptedCommand);
                        String command = new String(decryptedCommand);

                        if (command.equals("ls")) {
                            System.out.println("List of files");
                            File dir = new File("server");
                            File[] files = dir.listFiles((d, name) -> !name.endsWith(".prv"));

                            if (files == null || files.length == 0) {
                                System.out.println("No files available for download.");
                                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
                                byte[] encryptedResponse = aesCipher.doFinal("No files available for download.".getBytes());
                                dos.writeInt(encryptedResponse.length);
                                dos.write(encryptedResponse);
                            } else {
                                StringBuilder filesList = new StringBuilder();
                                for (File file : files) {
                                    if (!file.getName().endsWith(".prv")) {
                                        filesList.append(file.getName()).append("\n");
                                    }
                                }
                                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
                                byte[] encryptedFileList = aesCipher.doFinal(filesList.toString().getBytes());
                                dos.writeInt(encryptedFileList.length);
                                dos.write(encryptedFileList);
                            }
                        } else if (command.startsWith("get")) {
                            System.out.println("Getting file...");
                            String fileName = command.split(" ")[1];
                            File file = new File("server/" + fileName);

                            if (!file.exists() || file.isDirectory() || fileName.endsWith(".prv")) {
                                System.out.println("File not found or access denied: " + fileName);
                                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
                                byte[] encryptedResponse = aesCipher.doFinal("File not found or access denied".getBytes());
                                dos.writeInt(encryptedResponse.length);
                                dos.write(encryptedResponse);
                            } else {
                                System.out.println("Sending file: " + fileName);
                                byte[] fileContent = Files.readAllBytes(file.toPath());
                                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
                                byte[] encryptedResponse = aesCipher.doFinal(fileContent);
                                dos.writeInt(encryptedResponse.length);
                                dos.write(encryptedResponse);
                            }
                        } else if (command.equals("bye")) {
                            s.close();
                            break;
                        }
                    } catch (Exception e) {
                        System.err.println("Error processing command: " + e.getMessage());
                        e.printStackTrace();
                        break;
                    }
                }
            } catch (Exception e) {
                System.err.println("Error handling client connection: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
}