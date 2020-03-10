import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class Server {
    public static void main(String args[]) throws IOException{
        ServerSocket serverSocket = new ServerSocket(1234);
        
        while (true) {
            Socket serSocket = null;

            try {
                serSocket = serverSocket.accept();

                System.out.println("New User: " + serSocket);

                Thread tCli = new ClientHandler(serSocket, new Scanner(serSocket.getInputStream()), new PrintStream(serSocket.getOutputStream()));
                tCli.start();
            }
            catch (Exception e) {
                serSocket.close();
                e.printStackTrace();
            }
        }
        
    }
}

class ClientHandler extends Thread {
    final Scanner dataIn;
    final PrintStream dataOut;
    final Socket s;

    public ClientHandler(Socket s, Scanner dataIn, PrintStream dataOut) {
        this.s = s;
        this.dataIn = dataIn;
        this.dataOut = dataOut;
    }

    @Override
    public void run() {
        String cliReceived;
        String cliReturn;
        int board;

        while(true) {
            try {
                dataOut.println("Announcement (1) or General (2) Board?");
                cliReceived = String.valueOf(dataIn.nextInt());

                if (cliReceived.equals("1") | cliReceived.equals("2")) {
                    board = Integer.parseInt(cliReceived);
                    dataOut.println("Received");
                }
                else {
                    dataOut.println("Incorrect Input. Connect again...");
                    this.s.close();
                    break;
                }

                dataOut.println("Write your 255 characters max message:");
                cliReceived = dataIn.nextLine();

                dataOut.println("Message received.");
                this.s.close();
                break;
                //store message, verify bla bla bla
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

        try {
            this.dataIn.close();
            this.dataOut.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}