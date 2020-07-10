/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package client;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Random;


public class Client {

    private Socket socket = null;
    private DataInputStream in = null;
    private DataOutputStream out =null;

    private BigInteger PriKey;
    private BigInteger PubKey;
    private BigInteger ServerPublic;
    byte[] SessionKey;
    
    
    public Client (String ip, int port) throws IOException, NoSuchAlgorithmException {
        
            socket = new Socket(ip, port);
            System.out.println("Connected");
            
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());
            
            KeyExchangeGenarator ();
            KeyExchange(socket,  in,  out);
            SessionKeyGeneration();



             System.out.println(SessionKey.length);
            
            
            
            in.close();
            out.close(); 
            socket.close(); 
    }

    private void SessionKeyGeneration() throws NoSuchAlgorithmException {

        SessionKey =  ServerPublic.mod(PriKey).toString().getBytes();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(SessionKey);
        SessionKey = hash;
    }

    private void KeyExchange(Socket socket, DataInputStream in, DataOutputStream out) throws IOException {

        out.writeUTF(PubKey.toString());

        String line;
        line = in.readUTF();
        ServerPublic = new BigInteger(line);



    }

    private void KeyExchangeGenarator() throws NoSuchAlgorithmException {

        KeyPairGenerator keygenerator = KeyPairGenerator.getInstance("DH");
        keygenerator.initialize(2048);
        KeyPair keypair = keygenerator.generateKeyPair();

        PriKey = new BigInteger(keypair.getPrivate().getEncoded());
        PubKey = new BigInteger(keypair.getPublic().getEncoded());
    }


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        Client client = new Client("127.0.0.1", 5000);
    }
    
}
