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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;


public class Server {
    ConcurrentHashMap<PublicKey, ArrayList<Triplet>> registeredUsers;
    ConcurrentHashMap<Integer, Triplet> generalBoard;
    ConcurrentHashMap<PublicKey, SecureRandom> usersSeeds;
    AtomicInteger postCount;
    public static void main(String args[]) throws IOException{
        Server server = new Server();

        ServerSocket serverSocket = new ServerSocket(1234);
        server.registeredUsers = new ConcurrentHashMap<PublicKey, ArrayList<Triplet>>();
        server.generalBoard = new ConcurrentHashMap<Integer, Triplet>();
        server.usersSeeds = new ConcurrentHashMap<PublicKey, SecureRandom>();
        server.postCount = new AtomicInteger(0);
        
        while (true) {
            Socket serSocket = null;

            try {
                serSocket = serverSocket.accept();

                System.out.println("New User: " + serSocket);

                ClientHandler tCli = server.new ClientHandler(serSocket, new Scanner(serSocket.getInputStream()), new PrintStream(serSocket.getOutputStream()));
                tCli.start();
            }
            catch (Exception e) {
                serSocket.close();
                e.printStackTrace();
            }
        }   
    }

    class ClientHandler extends Thread {
        Scanner dataIn;
        PrintStream dataOut;
        Socket s;
    
        public ClientHandler(Socket s, Scanner dataIn, PrintStream dataOut) {
            this.s = s;
            this.dataIn = dataIn;
            this.dataOut = dataOut;
        }
    
        @Override
        public void run() {
            int cliInput;
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
    
            Server.this.usersSeeds.put(cliPublicKey, sr);
            Server.this.registeredUsers.put(cliPublicKey, tmpTripletList);
    
            //Sucess
            System.out.println("Client connected.");
        }
    
        public void post(boolean boardToPost) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException{
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
            Server.this.usersSeeds.get(cliPublicKey).nextBytes(nonce);
            md.update(nonce);
    
            byte verifyMessage[] = md.digest(message.getBytes());
    
            //Verify signature
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(cliPublicKey);
            signature.update(message.getBytes());
            boolean verifySignature = signature.verify(Base64.getDecoder().decode(this.dataIn.nextLine()));
    
            //Check references validity
            boolean refValidity = true;
            for (int i=0; i<references.length; i++) {
                if (references[i]>Server.this.postCount.get()) refValidity=false;
            }
    
            System.out.println(refValidity);
            System.out.println(verifySignature);
    
            if (Arrays.equals(hashedMessage, verifyMessage) && refValidity && verifySignature) {
                if (boardToPost) {
                    Triplet triplet = new Triplet(message, references, Server.this.postCount);
                    Server.this.registeredUsers.get(cliPublicKey).add(triplet);
                    System.out.println("Message posted to Announcement.");
                }
                else {
                    Triplet triplet = new Triplet(message, references, cliPublicKey);
                    Server.this.generalBoard.put(Server.this.postCount.get(), triplet);
                    System.out.println("Message posted to general.");
                }
                Server.this.postCount.incrementAndGet();
            }
            else {
                System.out.println("Message ignored.");
            }
        }
    
        public void read(boolean boardToRead) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException{
            int postsToRead = Integer.parseInt(this.dataIn.nextLine());
            if (postsToRead <= Server.this.postCount.get()) {
                this.dataOut.println("1");
                if (boardToRead) {
                    PublicKey cliPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(this.dataIn.nextLine())));
                    ArrayList<Triplet> messageList = Server.this.registeredUsers.get(cliPublicKey);
                    Collections.reverse(messageList);
                    for(Triplet t : messageList) {
                        if (postsToRead > 0) {
                            this.dataOut.println(t.msg);
                            postsToRead--;
                        }
                    }
                }
                else {
                    ArrayList<Integer> tmpList = new ArrayList<Integer>(Server.this.generalBoard.keySet());
                    int tmp = tmpList.size();
                    while(postsToRead > 0) {
                        this.dataOut.println(Server.this.generalBoard.get(tmpList.get(tmp-1)).msg);
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