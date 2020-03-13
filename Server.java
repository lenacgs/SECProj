import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;


public class Server {
    HashMap<PublicKey, ArrayList<Triplet>> registeredUsers;
    HashMap<Integer, Triplet> generalBoard;
    HashMap<PublicKey, SecureRandom> usersSeeds;
    int postCount;
    public static void main(String args[]) throws IOException{
        Server server = new Server();

        ServerSocket serverSocket = new ServerSocket(1234);
        server.registeredUsers = new HashMap<PublicKey, ArrayList<Triplet>>();
        server.generalBoard = new HashMap<Integer, Triplet>();
        server.usersSeeds = new HashMap<PublicKey, SecureRandom>();
        server.postCount = 0;
        
        while (true) {
            Socket serSocket = null;

            try {
                serSocket = serverSocket.accept();

                System.out.println("New User: " + serSocket);

                ClientHandler tCli = new ClientHandler(serSocket, new Scanner(serSocket.getInputStream()), new PrintStream(serSocket.getOutputStream()), server.registeredUsers, server.generalBoard, server.usersSeeds, server.postCount);
                tCli.start();
            }
            catch (Exception e) {
                serSocket.close();
                e.printStackTrace();
            }
        }   
    }
}

class Triplet {
    public String msg;
    public int[] postRef;
    public Object id;

    public Triplet(){}
    public Triplet(String msg, int[] postRef, Object id){
        this.msg = msg;
        this.postRef = postRef;
        this.id = id;
    }

    public void setMsg(String msg){
        this.msg = msg;
    }

    public void setPostRef(int[] postRef){
        this.postRef = postRef;
    }

    public void setId(Object id){
        this.id = id;
    }
}

class ClientHandler extends Thread {
    Scanner dataIn;
    PrintStream dataOut;
    Socket s;
    HashMap<PublicKey, ArrayList<Triplet>> registeredUsers;
    HashMap<Integer, Triplet> generalBoard;
    HashMap<PublicKey, SecureRandom> usersSeeds;
    int postCount;

    public ClientHandler(Socket s, Scanner dataIn, PrintStream dataOut, HashMap<PublicKey, ArrayList<Triplet>> registeredUsers, HashMap<Integer, Triplet> generalBoard, HashMap<PublicKey, SecureRandom> usersSeeds, int postCount) {
        this.s = s;
        this.dataIn = dataIn;
        this.dataOut = dataOut;
        this.registeredUsers = registeredUsers;
        this.generalBoard = generalBoard;
        this.usersSeeds = usersSeeds;
        this.postCount = postCount;
    }

    @Override
    public void run() {
        int cliInput;
        String cliReceived;
        boolean actionLoop=true;

        while(actionLoop) {
            try {
                cliInput = Integer.parseInt(this.dataIn.nextLine());
                switch (cliInput) {
                    case 0:
                        this.registerClient();
                        break;
                    case 1:
                        this.post(true);
                        break;
                    case 2:
                        this.post(false);
                        break;
                    case 3:
                        this.read(true);
                        break;
                    case 4:
                        this.read(false);
                        break;
                    case 5:
                        actionLoop=false;
                }
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

        try {
            this.s.close();
            this.dataIn.close();
            this.dataOut.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void registerClient() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException{
        //Extract Public Key
        PublicKey cliPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(this.dataIn.nextLine())));
        byte[] cliSeed = Base64.getDecoder().decode(this.dataIn.nextLine());
        
        //Init hashmaps with PublicKey obtained
        ArrayList<Triplet> tmpTripletList = new ArrayList<Triplet>();
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(cliSeed);

        this.usersSeeds.put(cliPublicKey, sr);
        this.registeredUsers.put(cliPublicKey, tmpTripletList);

        //Sucess
        System.out.println("Client connected.");
    }

    public void post(boolean boardToPost) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException{
        //Extract arguments
        PublicKey cliPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(this.dataIn.nextLine())));
        String message = this.dataIn.nextLine();

        String strRef = this.dataIn.nextLine();

        int[] references;
        if (strRef.length() > 0) {
            references = Arrays.stream(strRef.split(", ")).mapToInt(Integer::parseInt).toArray();
        }
        else {
            references = new int[]{};
        }

        byte hashedMessage[] = Base64.getDecoder().decode(this.dataIn.nextLine());

        //Verify nonce
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        byte nonce[] = new byte[20];
        usersSeeds.get(cliPublicKey).nextBytes(nonce);
        md.update(nonce);

        byte verifyMessage[] = md.digest(message.getBytes());

        //Check references validity
        boolean refValidity = true;
        for (int i=0; i<references.length; i++) {
            if (!(references[i]<postCount)) refValidity=false;
        }

        if (Arrays.equals(hashedMessage, verifyMessage) && refValidity) {
            if (boardToPost) {
                Triplet triplet = new Triplet(message, references, postCount);
                registeredUsers.get(cliPublicKey).add(triplet);
                System.out.println("Message posted to Announcement.");
            }
            else {
                Triplet triplet = new Triplet(message, references, cliPublicKey);
                generalBoard.put(postCount, triplet);
                System.out.println("Message posted to general.");
            }
            this.postCount++;
        }
        else {
            System.out.println("Message ignored.");
        }
    }

    public void read(boolean boardToRead) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException{
        int postsToRead = Integer.parseInt(this.dataIn.nextLine());
        if (postsToRead <= postCount) {
            this.dataOut.println("1");
            if (boardToRead) {
                PublicKey cliPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(this.dataIn.nextLine())));
                ArrayList<Triplet> messageList = registeredUsers.get(cliPublicKey);
                for(Triplet t : messageList) {
                    if (postsToRead > 0) {
                        this.dataOut.println(t.msg);
                        postsToRead--;
                    }
                }
            }
            else {
                int tmp = postCount;
                while(postsToRead > 0) {
                    this.dataOut.println(generalBoard.get(tmp-1).msg);
                    postsToRead--;
                    tmp--;
                }
            }
        }
        else {
            this.dataOut.println("0");
            System.out.println("Not enough posts to read.");
        }
    }
}