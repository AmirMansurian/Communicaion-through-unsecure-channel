/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;


public class Server {

    private Socket socket = null;
    private ServerSocket server = null;
    private DataInputStream input = null;
    private DataOutputStream output =null;

    private BigInteger PriKey;
    private BigInteger PubKey;
    private BigInteger ClientPublic;
    private byte[] SessionKey;

    
    public Server(int port) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        server = new ServerSocket(port);
            
        System.out.println("Server started"); 
  
        System.out.println("Waiting for a client ...");
            
        socket = server.accept();
        System.out.println("Client accepted"); 
            
        input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        output = new DataOutputStream(socket.getOutputStream());
        
        KeyExchangeGenarator();
        KeyExchange(socket, input, output);
        SessionKeyGeneration();
        
        Cryphtograpgy(input, output);
        
        
        
        output.close();
        socket.close();
        input.close();
    }

    private void Cryphtograpgy(DataInputStream input, DataOutputStream output) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {

        Key AESKey = new SecretKeySpec(SessionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, AESKey);
        System.out.println(Base64.getEncoder().encodeToString(SessionKey));

        String message = input.readUTF();
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decoded = decoder.decode(message);
        message = new String(cipher.doFinal(decoded));


    }

    private void SessionKeyGeneration() throws NoSuchAlgorithmException {

        SessionKey =  ClientPublic.mod(PriKey).toString().getBytes();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(SessionKey);
        SessionKey = hash;
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


    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Server server = new Server(5000);
    }
    
}
