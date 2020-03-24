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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.Key;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.io.*;


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


    KeyPair keyPair;

    
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException{
        Server server = new Server();

        ServerSocket serverSocket = new ServerSocket(1234);
        server.registeredUsers = new ConcurrentHashMap<PublicKey, ArrayList<Triplet>>();
        server.generalBoard = new ConcurrentHashMap<Integer, Triplet>();
        server.usersSeeds = new ConcurrentHashMap<PublicKey, SecureRandom>();
        server.postCount = new AtomicInteger(0);
        server.keyPair = initializeServerKeyPair("public_key","private_key");
        

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
    ConcurrentHashMap<PublicKey, ArrayList<Triplet>> registeredUsers;
    ConcurrentHashMap<Integer, Triplet> generalBoard;
    ConcurrentHashMap<PublicKey, SecureRandom> usersSeeds;
    AtomicInteger postCount;

    public ClientHandler(Socket s, Scanner dataIn, PrintStream dataOut, ConcurrentHashMap<PublicKey, ArrayList<Triplet>> registeredUsers, ConcurrentHashMap<Integer, Triplet> generalBoard, ConcurrentHashMap<PublicKey, SecureRandom> usersSeeds, AtomicInteger postCount) {
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
        usersSeeds.get(cliPublicKey).nextBytes(nonce);
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
            if (references[i]>postCount.get()) refValidity=false;
        }

        System.out.println(refValidity);
        System.out.println(verifySignature);

        if (Arrays.equals(hashedMessage, verifyMessage) && refValidity && verifySignature) {
            if (boardToPost) {
                Triplet triplet = new Triplet(message, references, postCount);
                registeredUsers.get(cliPublicKey).add(triplet);
                System.out.println("Message posted to Announcement.");
            }
            else {
                Triplet triplet = new Triplet(message, references, cliPublicKey);
                generalBoard.put(postCount.get(), triplet);
                System.out.println("Message posted to general.");
            }
            this.postCount.incrementAndGet();
        }
        else {
            System.out.println("Message ignored.");
        }
    }

    public void read(boolean boardToRead) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException{
        int postsToRead = Integer.parseInt(this.dataIn.nextLine());
        if (postsToRead <= postCount.get()) {
            this.dataOut.println("1");
            if (boardToRead) {
                PublicKey cliPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(this.dataIn.nextLine())));
                ArrayList<Triplet> messageList = registeredUsers.get(cliPublicKey);
                Collections.reverse(messageList);
                for(Triplet t : messageList) {
                    if (postsToRead > 0) {
                        this.dataOut.println(t.msg);
                        postsToRead--;
                    }
                }
            }
            else {
                ArrayList<Integer> tmpList = new ArrayList<Integer>(generalBoard.keySet());
                int tmp = tmpList.size();
                while(postsToRead > 0) {
                    this.dataOut.println(generalBoard.get(tmpList.get(tmp-1)).msg);
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