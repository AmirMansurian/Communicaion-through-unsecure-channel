/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;


public class Server {

    private Socket socket = null;
    private ServerSocket server = null;
    private DataInputStream input = null;
    private DataOutputStream output =null;

    private BigInteger Prime= new BigInteger("925b6a8281661b91b44ff23ffc3a2846f6e0d8ae519089d891e4b5c111a96c54c686d8c2bd599e8af6bdc3ff514756b2ba00b3adcfb912c297706bf02cc9c8ff84d0a122cfacbd4d818a9f1681fb3b202fbcba1301d59d1abaa1264ba52c1267ebd2bd9d39a9a6bb844327d3ffdf7bb26979a83caad578b0ecfbdbf8f0e28091f66c6e96b2c71ed6692e8126c8aeabc6113b6d8c2f6c36be0b806485ef72f58cbea6da92f72fef16b1fc9bac930a079be42d84de44fd63eeb8bb74462fe04f8b73cb9166cbd00a3f51b9cdaeb80d64ffcf9d61f09bc9c051c94707e970f9b3ee23fca379e7c82eb2cda76c5cd1911ae0cdffe29f0303e43a7ccf7d2821e5e24b", 16);
    private BigInteger Generator= new BigInteger("2");
    private BigInteger PriKey;
    private BigInteger PubKey;
    private BigInteger ClientPublic;
    private byte[] SessionKey;
    private byte[] IV = new byte[16];
    private int NumberOfMessage;

    
    public Server(int port) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
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

    private void Cryphtograpgy(DataInputStream input, DataOutputStream output) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        Key AESKey = new SecretKeySpec(SessionKey, "AES");
        IvParameterSpec IVV = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        String message = "";
        String Encrypted = "";
        String Decrypted = "";
        Scanner sc = new Scanner(System.in);
        NumberOfMessage = 0;

        while(true) {

            message = input.readUTF();
            Decrypted = Decryption(cipher, AESKey, IVV, message);
            System.out.println("Message from Client : " + Decrypted);
            NumberOfMessage++;
            if (Decrypted == "bye" || Decrypted =="Bye")
                break;

            if (NumberOfMessage == 2)
            {
                NumberOfMessage = 0;
                String nounce = new BigInteger(512, new SecureRandom()).toString();
                output.writeUTF(nounce);
                Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
                SecretKeySpec secret_key = new SecretKeySpec(nounce.getBytes(), "HmacSHA256");
                sha256_HMAC.init(secret_key);
                SessionKey = sha256_HMAC.doFinal(message.getBytes());
                System.out.println("Session Key Changed !!!");
            }


            message = sc.nextLine();
            Encrypted = Encrytion(cipher, AESKey, IVV, message);
            output.writeUTF(Encrypted);
            System.out.println("Message to Client : " + Encrypted);
            NumberOfMessage++;
            if (message == "bye" || message =="Bye")
                break;

            if (NumberOfMessage == 2)
            {
                NumberOfMessage = 0;
                String nounce = input.readUTF();
                Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
                SecretKeySpec secret_key = new SecretKeySpec(nounce.getBytes(), "HmacSHA256");
                sha256_HMAC.init(secret_key);
                SessionKey = sha256_HMAC.doFinal(message.getBytes());
                System.out.println("Session Key Changed !!!");
            }
        }
    }

    private String Decryption(Cipher cipher, Key AESKey, IvParameterSpec IVV, String message) throws BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException {

        cipher.init(Cipher.DECRYPT_MODE, AESKey, IVV);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decoded = decoder.decode(message);
        message = new String(cipher.doFinal(decoded), "UTF-8");

        String hmac = message.substring(message.length()-32, message.length());
        message = message.substring(0, message.length()-32);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        String hash = new String(encodedhash, "UTF-8");
        int len = 32 - hash.length();
        for (int i=0; i<len; i++)
            hash = "a" + hash;

        if (!hash.equals(hmac))
            return"Integrity Fault";

        return message;
    }

    private String Encrytion(Cipher cipher, Key AESKey, IvParameterSpec IVV, String message) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        cipher.init(Cipher.ENCRYPT_MODE, AESKey, IVV);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        String hash = new String(encodedhash, "UTF-8");
        int len = 32 - hash.length();
        for (int i=0; i<len; i++)
            hash = "a" + hash;

        byte[] encoded = cipher.doFinal((message+hash).getBytes());
        message = Base64.getEncoder().encodeToString(encoded);

        return message;
    }



    private void SessionKeyGeneration() throws NoSuchAlgorithmException {

        SessionKey =  ClientPublic.modPow(PriKey, Prime).toString().getBytes();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(SessionKey);
        SessionKey = hash;
    }

    private void KeyExchange(Socket socket, DataInputStream input, DataOutputStream output) throws IOException {

        String line = input.readUTF();
        ClientPublic = new BigInteger(line);
        output.writeUTF(PubKey.toString());
    }

    private void KeyExchangeGenarator() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        BigInteger bigInteger = Prime.subtract(new BigInteger("2"));
        Random randNum = new Random();
        int len = Prime.bitLength();
        BigInteger res = new BigInteger(len, randNum);
        if (res.compareTo(new BigInteger("2")) < 0)
            res = res.add(new BigInteger("2"));
        if (res.compareTo(bigInteger) >= 0)
            res = res.mod(bigInteger).add(new BigInteger("2"));

        PriKey = res;
        PubKey = Generator.modPow(PriKey, Prime);
    }


    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Server server = new Server(5000);
    }
    
}
