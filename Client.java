import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.Key;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;



public class Client{

    private KeyPair cliKeyPair;
    private SecureRandom cliSr;
    int clientId;

    public Scanner cliScanner; //Scan user inputs
    public Socket cliSocket; //Socket for server-client communication
    public Scanner dataIn; //Data input from server
    public PrintStream dataOut; //Data output to server

    public static void main(String args[]) throws IOException{
        try {
            int cliInput;
            String cliMessage;
            String cliReference;
            String[] cliReferenceArray;
            boolean actionLoop = true;
            int id;
            if(args.length > 0) {
                id = Integer.parseInt(args[0]);
            }else{
                id = 69;
            }

            Client cli = new Client(id);
            cli.register(cli.getPublicKey());


            System.out.println("Client connected with key: " + cli.getPublicKey());

            while(actionLoop) {
                System.out.println("Choose:");
                System.out.println("1. Post Announcement");
                System.out.println("2. Post General");
                System.out.println("3. Read Announcement");
                System.out.println("4. Read General");
                System.out.println("5. Disconnect");
                cliInput = Integer.parseInt(cli.cliScanner.nextLine());

                switch (cliInput) {
                    case 1: 
                        System.out.println("255 Characters Max message: ");
                        cliMessage = cli.cliScanner.nextLine(); //get user message
                        System.out.println("Announcement References (separated with commas): ");
                        cliReference = cli.cliScanner.nextLine(); //get user references
                        cliReferenceArray = cliReference.split(",");
                        cli.post(cli.getPublicKey(), cliMessage, cliReferenceArray); 
                        break;
                    case 2: 
                        System.out.println("255 Characters Max message: ");
                        cliMessage = cli.cliScanner.nextLine(); //get user message
                        System.out.println("Announcement References (separated with commas): ");
                        cliReference = cli.cliScanner.nextLine(); //get user references
                        cliReferenceArray = cliReference.split(",");
                        cli.postGeneral(cli.getPublicKey(), cliMessage, cliReferenceArray);
                        break;
                    case 3: 
                        System.out.println("Number of posts to read: ");
                        cli.read(cli.getPublicKey(), Integer.parseInt(cli.cliScanner.nextLine()));
                        break;
                    case 4: 
                        System.out.println("Number of posts to read: ");
                        cli.readGeneral(Integer.parseInt(cli.cliScanner.nextLine()));
                        break;      
                    case 5: 
                        System.out.println("Disconnecting...");
                        cli.dataOut.println("5");
                        actionLoop=false;
                        break;
                }

            }

            cli.cliScanner.close();
            cli.dataIn.close();
            cli.dataOut.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Client(int id) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException, KeyStoreException{
        //Keys

        this.cliSr = SecureRandom.getInstance("SHA1PRNG");

        this.clientId = id;

        this.cliKeyPair = initializeClientKeyPair("clientPublicKey" + this.clientId,"clientPrivateKey" + this.clientId);

        //Communication
        this.cliScanner = new Scanner(System.in);
        this.cliSocket = new Socket("127.0.0.1", 1234);
            
        this.dataIn = new Scanner(cliSocket.getInputStream());
        this.dataOut = new PrintStream(cliSocket.getOutputStream());
    }

    public PublicKey getPublicKey() {
        return this.cliKeyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return  this.cliKeyPair.getPrivate();
    }

    public void register(PublicKey key) throws IOException {
        this.dataOut.println("0");
        this.dataOut.println(Base64.getEncoder().encodeToString(key.getEncoded()));

        //Nonce seed
        byte[] seed = this.cliSr.generateSeed(32);
        this.cliSr.setSeed(seed);
        this.dataOut.println(Base64.getEncoder().encodeToString(seed));
    }

    public void post(PublicKey key, String message, String[] a) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
        //Create Signature
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(this.getPrivateKey());
        signature.update(message.getBytes());

        //Create Nonce
        byte nonce[] = new byte[20];
        this.cliSr.nextBytes(nonce);

        //Message Digest
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(nonce);

        byte hashedMessage[] = md.digest(message.getBytes());

        //Send data to server
        this.dataOut.println("1");
        this.dataOut.println(Base64.getEncoder().encodeToString(key.getEncoded()));
        this.dataOut.println(message);
        this.dataOut.println(String.join(", ", a));
        this.dataOut.println(Base64.getEncoder().encodeToString(hashedMessage));
        this.dataOut.println(Base64.getEncoder().encodeToString(signature.sign()));
    }

    public void postGeneral(PublicKey key, String message, String[] a) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
        //Create Signature
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(this.getPrivateKey());
        signature.update(message.getBytes());

        //Create Nonce
        byte nonce[] = new byte[20];
        this.cliSr.nextBytes(nonce);

        //Message Digest
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(nonce);

        byte hashedMessage[] = md.digest(message.getBytes());
        this.dataOut.println("2");
        this.dataOut.println(Base64.getEncoder().encodeToString(key.getEncoded()));
        this.dataOut.println(message);
        this.dataOut.println(String.join(", ", a));
        this.dataOut.println(Base64.getEncoder().encodeToString(hashedMessage));
        this.dataOut.println(Base64.getEncoder().encodeToString(signature.sign()));

    }

    public void read(PublicKey key, int number) {
        this.dataOut.println("3");
        this.dataOut.println(String.valueOf(number));
        this.dataOut.println(Base64.getEncoder().encodeToString(key.getEncoded()));
        
        //Verify input errors
        if (this.dataIn.nextLine().equals("1")) {
            while (number > 0) {
                System.out.println(this.dataIn.nextLine());
                number--;
            }
        }
        else {
            System.out.println("Invalid input.");
        }
    }

    public void readGeneral(int number) {
        this.dataOut.println("4");
        this.dataOut.println(String.valueOf(number));

        //Verify input errors
        if (this.dataIn.nextLine().equals("1")) {
            while (number > 0) {
                System.out.println(this.dataIn.nextLine());
                number--;
            }
        }
        else {
            System.out.println("Invalid input.");
        }
    }

    public KeyPair initializeClientKeyPair(String publicKeyPath,String privateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException {

        File pubf = new File(publicKeyPath );
        File privf = new File(privateKeyPath );

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
     void writeKey(Key key, String path) throws IOException, KeyStoreException {

        byte[] encoded = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(encoded);
        fos.close();

    }




}