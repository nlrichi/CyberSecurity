import java.io.*;
import java.net.*;
import java.util.*;
public class Client {
    public static void main(String [] args) throws Exception {

        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]);           // port of server
        String userid = args[2]; //userid of client
        Socket s = new Socket(host, port);
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());
        DataInputStream dis = new DataInputStream(s.getInputStream());

        System.out.println("Enter the file name you would like to download ");
        Scanner sc = new Scanner(System.in);
        String aLine = sc.nextLine();

        while ((aLine = sc.nextLine()) != null) {

            dos.writeUTF(aLine);
            System.out.println(dis.readUTF());

        }

    }
}