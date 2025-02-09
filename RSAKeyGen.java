import java.io.*;
import java.security.*;
/*This class generates matching public/private RSA keys.*/
public class RSAKeyGen {
    public static void main(String args[]) throws Exception {
        if(args.length != 1) {
            System.err.println("Usage: java RSAKeyGen userid");
            System.exit(1);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        FileOutputStream fos = new FileOutputStream(args[0] + ".pub");
        fos.write(kp.getPublic().getEncoded());
        fos.close();

        fos = new FileOutputStream(args[0] + ".prv");
        fos.write(kp.getPrivate().getEncoded());
        fos.close();
    }

    if (args[0].equals("-e")) {

        // read key
        File f = new File("alice.pub");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf.generatePublic(pubSpec);

        // taking input
        System.out.println("Enter a message: ");
        Scanner sc = new Scanner(System.in);
        String msg = sc.nextLine();

        // encrypt
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] raw = cipher.doFinal(msg.getBytes("UTF8"));

        // write to file
        File file = new File("encrypted.msg");
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(raw);
        fos.close();

    }
		else if (args[0].equals("-d")) {

        // read key
        File f = new File("alice.prv");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey prvKey = kf.generatePrivate(prvSpec);

        // read file
        File file = new File("encrypted.msg");
        byte[] raw = Files.readAllBytes(file.toPath());

        // decrypt
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, prvKey);
        byte[] stringBytes = cipher.doFinal(raw);
        String result = new String(stringBytes, "UTF8");
        System.out.println(result);
    }


}
