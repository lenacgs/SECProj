import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.Key;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;



public class Server {

    public static String filenames[] = {"registeredUsers.ser","generalBoard.ser","usersSeeds.ser","postCount.ser"};

    ConcurrentHashMap<PublicKey, ArrayList<Triplet>> registeredUsers;
    ConcurrentHashMap<Integer, Triplet> generalBoard;
    ConcurrentHashMap<PublicKey, ArrayList<String>> usersSeeds;
    AtomicInteger postCount;
    

    private void saveServerState(){
        saveFile(registeredUsers,filenames[0]);
        saveFile(generalBoard,filenames[1]);
        saveFile(usersSeeds,filenames[2]);
        saveFile(postCount,filenames[3]);
    }

    private void saveFile(Object o,String filename) {
        try{
            FileOutputStream file = new FileOutputStream(filename + "_tmp");
            ObjectOutputStream out = new ObjectOutputStream(file);

            out.writeObject(o);

            out.close();
            file.close();

            Files.move(Paths.get( filename + "_tmp"), Paths.get(filename), StandardCopyOption.ATOMIC_MOVE);

        } catch (FileNotFoundException fnfe){
            System.out.println("Error writing file state for " + filename);
        } catch(IOException ioe){
            System.out.println("Error updating temp file to " + filename);
        } catch(Exception e){
            System.out.println("Unknown error saving state for " + filename + ":" + e.getMessage());
        }
    }
    
    @SuppressWarnings("unchecked")
    private void loadServerState(){
        Object result;
        registeredUsers = (result = loadFile(filenames[0]))==null?new ConcurrentHashMap<PublicKey, ArrayList<Triplet>>():(ConcurrentHashMap<PublicKey, ArrayList<Triplet>>)result;
        generalBoard = (result = loadFile(filenames[1]))==null?new ConcurrentHashMap<Integer, Triplet>():(ConcurrentHashMap<Integer, Triplet>)result;
        usersSeeds = (result = loadFile(filenames[2]))==null?new ConcurrentHashMap<PublicKey, ArrayList<String>>():(ConcurrentHashMap<PublicKey, ArrayList<String>>)result;
        postCount = (result = loadFile(filenames[3]))==null?new AtomicInteger(0):(AtomicInteger)result;
    }

    private Object loadFile(String filename){
        Object o = null;
        try {
            FileInputStream file = new FileInputStream(filename);
            ObjectInputStream in = new ObjectInputStream(file);

            o = in.readObject();

            in.close();
            file.close();
        } catch (FileNotFoundException fnfe){
            //Situação de primeira vez correr a aplicação sem gravar previamente os ficheiros
            //System.out.println("Error loading file state for " + filename);
        } catch(Exception e){
            System.out.println("Unknown error reading state for " + filename + ":" + e.getMessage());
        }
        return o;
    }
    SecureRandom serSr;

    KeyPair keyPair;

    
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException{
        Server server = new Server();

        ServerSocket serverSocket = new ServerSocket(1234);
        //Serialization
        server.loadServerState();
        Runtime.getRuntime().addShutdownHook(server.new UpdateServer());
        
        
        server.keyPair = initializeServerKeyPair("public_key.key","private_key.key");
        server.serSr = SecureRandom.getInstance("SHA1PRNG");

        
            Socket serSocket = null;
            try {
                while (true) {

                    serSocket = serverSocket.accept();

                    System.out.println("New User: " + serSocket);

                    ClientHandler tCli = server.new ClientHandler(serSocket, new Scanner(serSocket.getInputStream()), new PrintStream(serSocket.getOutputStream()));
                    tCli.start();
                }   
            }
            catch (Exception e) {
                if (serSocket != null) serSocket.close();
                e.printStackTrace();
            }
            finally {
                serverSocket.close();
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
            this.dataOut.flush();

            //Extract Public Key
            PublicKey cliPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(this.dataIn.nextLine())));
            
            //Init hashmaps with PublicKey obtained
            ArrayList<Triplet> tmpTripletList = new ArrayList<Triplet>();
    
            Server.this.usersSeeds.putIfAbsent(cliPublicKey, new ArrayList<String>());
            Server.this.registeredUsers.putIfAbsent(cliPublicKey, tmpTripletList);

            this.dataOut.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    
            //Sucess
            System.out.println("Client connected.\n");
            Server.this.saveFile(registeredUsers, Server.filenames[0]);
        }
    
        public void post(boolean boardToPost) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException{
            this.dataOut.flush();

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
    
            //Verify nonce
            MessageDigest md = MessageDigest.getInstance("SHA-1");
    
            String nonceS = this.dataIn.nextLine();

            byte[] nonce = Base64.getDecoder().decode(nonceS);
            md.update(nonce);
    
            byte hashedMessage[] = md.digest(message.getBytes());
    
            //Verify signature
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(cliPublicKey);
            signature.update(hashedMessage);
            boolean verifySignature = signature.verify(Base64.getDecoder().decode(this.dataIn.nextLine()));
    
            //Check references validity
            boolean refValidity = true;
            for (int i=0; i<references.length; i++) {
                if (references[i]>Server.this.postCount.get()) refValidity=false;
            }
    
            boolean nonceValidity = !(usersSeeds.get(cliPublicKey).contains(nonceS));

            System.out.println("References valid: " + refValidity);
            System.out.println("Signature valid: " + verifySignature);
            System.out.println("Nonce valid: " + nonceValidity);
            if (refValidity && verifySignature && nonceValidity) {
                usersSeeds.get(cliPublicKey).add(nonceS);
                if (boardToPost) {
                    Triplet triplet = new Triplet(message, references, Server.this.postCount);
                    Server.this.registeredUsers.get(cliPublicKey).add(triplet);
                    System.out.println("Message posted to Announcement.\n");
                }
                else {
                    Triplet triplet = new Triplet(message, references, cliPublicKey);
                    Server.this.generalBoard.put(Server.this.postCount.get(), triplet);
                    System.out.println("Message posted to general.\n");
                }
                Server.this.postCount.incrementAndGet();
            }
            else {
                System.out.println("Message ignored.\n");
            }
            
            if(boardToPost){
                Server.this.saveFile(usersSeeds, Server.filenames[2]);
            } else {
                Server.this.saveFile(generalBoard, Server.filenames[1]);
            }
            Server.this.saveFile(postCount, Server.filenames[3]);
        }
    
        public void read(boolean boardToRead) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException {
            this.dataOut.flush();

            //Create Signature
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(keyPair.getPrivate());

            //Create Nonce
            byte nonce[];

            //Message Digest
            MessageDigest md = MessageDigest.getInstance("SHA-1");

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

                            //Signature and Nonce
                            nonce = new byte[20];
                            serSr.nextBytes(nonce);
                            this.dataOut.println(Base64.getEncoder().encodeToString(nonce));
                            md.update(nonce);

                            byte hashedMessage[] = md.digest(t.msg.getBytes());
                            signature.update(hashedMessage);

                            this.dataOut.println(Base64.getEncoder().encodeToString(signature.sign()));

                            postsToRead--;
                        }
                    }
                }
                else {
                    ArrayList<Integer> tmpList = new ArrayList<Integer>(Server.this.generalBoard.keySet());
                    int tmp = tmpList.size();
                    while(postsToRead > 0) {
                        String msg = Server.this.generalBoard.get(tmpList.get(tmp-1)).msg;
                        this.dataOut.println(msg);
                        
                        //Signature and Nonce
                        nonce = new byte[20];
                        serSr.nextBytes(nonce);
                        this.dataOut.println(Base64.getEncoder().encodeToString(nonce));
                        md.update(nonce);

                        byte hashedMessage[] = md.digest(msg.getBytes());
                        signature.update(hashedMessage);

                        this.dataOut.println(Base64.getEncoder().encodeToString(signature.sign()));

                        postsToRead--;
                        tmp--;
                    }
                }
            }
            else {
                if (boardToRead) {
                    this.dataIn.nextLine();
                }
                this.dataOut.println("0");
                System.out.println("Not enough posts to read.");
            }
        }
    }

    class UpdateServer extends Thread{
        @Override
        public void run(){
            Server.this.saveServerState();
            Arrays.stream(Server.filenames).forEach(filename -> (new File(filename + "_tmp")).delete());
        }
    }
    public static KeyPair initializeServerKeyPair(String publicKeyPath,String privateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException {

        File pubf = new File(publicKeyPath);
        File privf = new File(privateKeyPath);

        if(pubf.exists() && privf.exists()) {

            FileInputStream fpub = new FileInputStream(publicKeyPath);
            FileInputStream fpriv = new FileInputStream(privateKeyPath);

            byte[] encodedPub = new byte[fpub.available()];
            byte[] encodedPriv = new byte[fpriv.available()];
            fpub.read(encodedPub);
            fpub.close();
            fpriv.read(encodedPriv);
            fpriv.close();

            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encodedPub);
            KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
            PublicKey pub = keyFacPub.generatePublic(pubSpec);

            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encodedPriv);

            KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
            PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

            return new KeyPair(pub,priv);
        }


        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        writeKey(keyPair.getPublic(),publicKeyPath);
        writeKey(keyPair.getPrivate(),privateKeyPath);
        return keyPair;


    }
    static void writeKey(Key key, String path) throws IOException, KeyStoreException {

        byte[] encoded = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(encoded);
        fos.close();

    }
}

class Triplet implements Serializable {
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