/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;


public class Server {

    private Socket socket = null;
    private ServerSocket server = null;
    private DataInputStream input = null;
    private DataOutputStream output =null;

    private BigInteger PriKey;
    private BigInteger PubKey;
    private BigInteger ClientPublic;
    private String SessionKey;

    
    public Server(int port) throws IOException, NoSuchAlgorithmException {
        server = new ServerSocket(port);
            
        System.out.println("Server started"); 
  
        System.out.println("Waiting for a client ...");
            
        socket = server.accept();
        System.out.println("Client accepted"); 
            
        input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        output = new DataOutputStream(socket.getOutputStream());
        
        KeyExchangeGenarator();
        KeyExchange(socket, input, output);
        
        
        
        
        
        
        output.close();
        socket.close();
        input.close();
    }

    private void SessionKeyGeneration() {

        SessionKey =  ClientPublic.mod(PriKey).toString();
    }

    private void KeyExchange(Socket socket, DataInputStream input, DataOutputStream output) throws IOException {

        String line = input.readUTF();
        ClientPublic = new BigInteger(line);

        output.writeUTF(PubKey.toString());

    }

    private void KeyExchangeGenarator() throws NoSuchAlgorithmException {

        KeyPairGenerator keygenerator = KeyPairGenerator.getInstance("DH");
        keygenerator.initialize(2048);
        KeyPair keypair = keygenerator.generateKeyPair();

        PriKey = new BigInteger(keypair.getPrivate().getEncoded());
        PubKey = new BigInteger(keypair.getPublic().getEncoded());
    }


    
    public static void main(String[] args) {
        // TODO code application logic here
    }
    
}
