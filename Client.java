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

public class Client{

    private KeyPairGenerator cliKeyPairGenerator;
    private KeyPair cliKeyPair;
    private PublicKey cliPublicKey;
    private PrivateKey cliPrivateKey;
    private SecureRandom cliSr;

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
            Client cli = new Client();
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

    public Client() throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
        //Keys
        this.cliKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        this.cliKeyPairGenerator.initialize(2048);
        this.cliKeyPair = this.cliKeyPairGenerator.generateKeyPair();
        this.cliPublicKey = this.cliKeyPair.getPublic();
        this.cliPrivateKey = this.cliKeyPair.getPrivate();
        this.cliSr = SecureRandom.getInstance("SHA1PRNG");

        //Communication
        this.cliScanner = new Scanner(System.in);
        this.cliSocket = new Socket("127.0.0.1", 1234);
            
        this.dataIn = new Scanner(cliSocket.getInputStream());
        this.dataOut = new PrintStream(cliSocket.getOutputStream());
    }

    public PublicKey getPublicKey() {
        return this.cliPublicKey;
    }

    public PrivateKey getPrivateKey() {
        return this.cliPrivateKey;
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
}