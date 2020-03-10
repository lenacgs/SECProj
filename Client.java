import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Scanner;

public class Client {
    public static void main(String args[]) throws IOException{
        try {
            Scanner cliScanner = new Scanner(System.in);
            Socket cliSocket = new Socket("127.0.0.1", 1234);
            
            Scanner dataIn = new Scanner(cliSocket.getInputStream());
            PrintStream dataOut = new PrintStream(cliSocket.getOutputStream());

            while(true) {
                System.out.println(dataIn.nextLine());//choose board message
                dataOut.println(cliScanner.nextLine());//respond with 1 or 2

                System.out.println(dataIn.nextLine());//server answer "received" or "incorrect"

                System.out.println(dataIn.nextLine());//write message message
                dataOut.println(cliScanner.nextLine());//respond with message

                System.out.println(dataIn.nextLine());//server answer "message received"
                break;
            }

            cliScanner.close();
            dataIn.close();
            dataOut.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}