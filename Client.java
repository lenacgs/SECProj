import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
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
import java.security.KeyStoreException;
import java.security.Key;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;



public class Client{

    private PublicKey serPublicKey;
    private ArrayList<String> serSeeds;
    private KeyPair cliKeyPair;
    private SecureRandom cliSr;
    int clientId;

    public Scanner cliScanner; //Scan user inputs
    public Socket cliSocket; //Socket for server-client communication
    public Scanner dataIn; //Data input from server
    public PrintStream dataOut; //Data output to server

    public byte[] usedNonce; //Tests purpose
    public boolean repeatNonce = false; //Tests purpose
    public PrivateKey testSignatureKey; //Tests purpose
    public boolean failSignature = false; //Tests purpose

    public static void main(String args[]) throws IOException{
        try {
            int cliInput;
            String cliMessage;
            String cliReference;
            String[] cliReferenceArray;
            String cliKeyFile;
            boolean actionLoop = true;
            int id;
            boolean testFlag = false;
            
            if(args.length > 0) {
                id = Integer.parseInt(args[0]);
                if (args.length > 1 && Integer.parseInt(args[1]) == 1) {
                    testFlag = true;
                }
            }else{
                id = 69;
            }

            Client cli = new Client(id);
            cli.register(cli.getPublicKey());


            System.out.println("Client connected with key: " + cli.getPublicKey());

            if (testFlag) {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();

                cli.testSignatureKey = keyPair.getPrivate();

                String[] wrongReferences = new String[1];
                wrongReferences[0] = "1";
                String[] correctReferences = new String[0];

                cli.post(cli.getPublicKey(), "Mensagem de Erro", wrongReferences); //Referencias erradas

                cli.failSignature = true;
                cli.post(cli.getPublicKey(), "Mensagem de Erro", correctReferences); //Assinatura errada
                cli.failSignature = false;

                cli.post(cli.getPublicKey(), "Mensagem correta", correctReferences); //Mensagem correta para gerar um nonce e usa lo para testar replay attack

                cli.repeatNonce = true;
                cli.post(cli.getPublicKey(), "Mensagem de Erro", correctReferences); //Nonce errado
                cli.repeatNonce = false;

                System.out.println("Tests done.\n");
            }
            //else{
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
                            System.out.println("Public Key associated with announcement board: ");
                            cliKeyFile = cli.cliScanner.nextLine();
    
                            File pubf = new File(cliKeyFile);
                            if(pubf.exists()) {
    
                                FileInputStream fpub = new FileInputStream(cliKeyFile);
                    
                                byte[] encodedPub = new byte[fpub.available()];
                                fpub.read(encodedPub);
                                fpub.close();
                    
                                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encodedPub);
                                KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
                                PublicKey pub = keyFacPub.generatePublic(pubSpec);
    
                                System.out.println("Number of posts to read: ");
                                cli.read(pub, Integer.parseInt(cli.cliScanner.nextLine()));
                            }
                            else{
                                System.out.println("Error with key file input.");
                            }
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
            //}

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

        this.cliKeyPair = initializeClientKeyPair("clientPublicKey" + this.clientId + ".key","clientPrivateKey" + this.clientId + ".key");

        this.serSeeds = new ArrayList<String>();
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

    public void register(PublicKey key) throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        this.dataOut.flush();

        this.dataOut.println("0");
        this.dataOut.println(Base64.getEncoder().encodeToString(key.getEncoded()));

        this.serPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(this.dataIn.nextLine())));
    }

    public void post(PublicKey key, String message, String[] a) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
        this.dataOut.flush();

        //Create Nonce
        byte nonce[] = new byte[15];
        this.cliSr.nextBytes(nonce);

        //For tests purpose
        if (!(repeatNonce)) {
            //Save the nonce for a replay attack test
            usedNonce = nonce;
        }
        else {
            //Use the previously saved nonce for testing
            nonce = usedNonce;
        }

        //Message Digest
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(nonce);

        byte hashedMessage[] = md.digest(message.getBytes());

        //Create Signature
        Signature signature = Signature.getInstance("SHA1withRSA");
        
        //For Tests purpose
        if (failSignature) {
            signature.initSign(this.testSignatureKey);
        }
        else {
            signature.initSign(this.getPrivateKey());
        }
        signature.update(hashedMessage);

        //Send data to server
        this.dataOut.println("1");
        this.dataOut.println(Base64.getEncoder().encodeToString(key.getEncoded()));
        this.dataOut.println(message);
        this.dataOut.println(String.join(", ", a));
        this.dataOut.println(Base64.getEncoder().encodeToString(nonce));
        this.dataOut.println(Base64.getEncoder().encodeToString(signature.sign()));
    }

    public void postGeneral(PublicKey key, String message, String[] a) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
        this.dataOut.flush();

        //Create Nonce
        byte nonce[] = new byte[20];
        this.cliSr.nextBytes(nonce);

        //Message Digest
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(nonce);

        byte hashedMessage[] = md.digest(message.getBytes());

        //Create Signature
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(this.getPrivateKey());
        signature.update(hashedMessage);

        this.dataOut.println("2");
        this.dataOut.println(Base64.getEncoder().encodeToString(key.getEncoded()));
        this.dataOut.println(message);
        this.dataOut.println(String.join(", ", a));
        this.dataOut.println(Base64.getEncoder().encodeToString(nonce));
        this.dataOut.println(Base64.getEncoder().encodeToString(signature.sign()));

    }

    public void read(PublicKey key, int number) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException {
        this.dataOut.flush();

        this.dataOut.println("3");
        this.dataOut.println(String.valueOf(number));
        this.dataOut.println(Base64.getEncoder().encodeToString(key.getEncoded()));
        
        //Verify input errors
        if (this.dataIn.nextLine().equals("1")) {
            while (number > 0) {
                String message = this.dataIn.nextLine();

                //Verify message
                MessageDigest md = MessageDigest.getInstance("SHA-1");
        
                String nonceS = this.dataIn.nextLine();

                byte nonce[] = Base64.getDecoder().decode(nonceS);
                md.update(nonce);
        
                byte hashedMessage[] = md.digest(message.getBytes());
        
                //Verify signature
                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initVerify(serPublicKey);
                signature.update(hashedMessage);
                boolean verifySignature = signature.verify(Base64.getDecoder().decode(this.dataIn.nextLine()));

                if (verifySignature && !(serSeeds.contains(nonceS))) {
                    serSeeds.add(nonceS);
                    System.out.println(message);
                }
                else {
                    System.out.println("Message was tampered with.");
                    break;
                }

                number--;
            }
        }
        else {
            System.out.println("Invalid input.");
        }
    }

    public void readGeneral(int number) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException {
        this.dataOut.flush();

        this.dataOut.println("4");
        this.dataOut.println(String.valueOf(number));

        //Verify input errors
        if (this.dataIn.nextLine().equals("1")) {
            while (number > 0) {
                String message = this.dataIn.nextLine();

                //Verify message
                MessageDigest md = MessageDigest.getInstance("SHA-1");
        
                String nonceS = this.dataIn.nextLine();

                byte nonce[] = Base64.getDecoder().decode(nonceS);
                md.update(nonce);
        
                byte hashedMessage[] = md.digest(message.getBytes());
        
                //Verify signature
                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initVerify(serPublicKey);
                signature.update(hashedMessage);
                boolean verifySignature = signature.verify(Base64.getDecoder().decode(this.dataIn.nextLine()));
                
                if (verifySignature && !(serSeeds.contains(nonceS))) {
                    serSeeds.add(nonceS);
                    System.out.println(message);
                }
                else {
                    System.out.println("Message was tampered with.");
                    break;
                }

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