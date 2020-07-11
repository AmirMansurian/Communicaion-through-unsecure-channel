/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package client;

import javax.crypto.*;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;


public class Client {

    private Socket socket = null;
    private DataInputStream in = null;
    private DataOutputStream out =null;

    private BigInteger Prime= new BigInteger("925b6a8281661b91b44ff23ffc3a2846f6e0d8ae519089d891e4b5c111a96c54c686d8c2bd599e8af6bdc3ff514756b2ba00b3adcfb912c297706bf02cc9c8ff84d0a122cfacbd4d818a9f1681fb3b202fbcba1301d59d1abaa1264ba52c1267ebd2bd9d39a9a6bb844327d3ffdf7bb26979a83caad578b0ecfbdbf8f0e28091f66c6e96b2c71ed6692e8126c8aeabc6113b6d8c2f6c36be0b806485ef72f58cbea6da92f72fef16b1fc9bac930a079be42d84de44fd63eeb8bb74462fe04f8b73cb9166cbd00a3f51b9cdaeb80d64ffcf9d61f09bc9c051c94707e970f9b3ee23fca379e7c82eb2cda76c5cd1911ae0cdffe29f0303e43a7ccf7d2821e5e24b", 16);
    private BigInteger Generator= new BigInteger("2");
    private BigInteger PriKey;
    private BigInteger PubKey;
    private BigInteger ServerPublic;
    private byte[] SessionKey;
    private byte[] IV = new byte[16];
    private int NumberOfMessage;
    
    
    public Client (String ip, int port) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        
            socket = new Socket(ip, port);
            System.out.println("Connected");
            
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());
            
            KeyExchangeGenarator ();
            KeyExchange(socket,  in,  out);
            SessionKeyGeneration();
            Cryptography(in ,out);

            in.close();
            out.close(); 
            socket.close(); 
    }

    private void Cryptography(DataInputStream in, DataOutputStream out) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {

        Key AESKey = new SecretKeySpec(SessionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec IVV = new IvParameterSpec(IV);
        String message = "hiiiiiii";
        String Encrypted = "";
        String Decrypted = "";
        Scanner sc = new Scanner(System.in);
        NumberOfMessage = 0;

        while (true) {

            message = sc.nextLine();
            Encrypted = Encrytion(cipher, AESKey, IVV, message);
            out.writeUTF(Encrypted);
            System.out.println("Message to Server : " + Encrypted);
            NumberOfMessage++;
            if (message == "bye" || message =="Bye")
                break;

            if (NumberOfMessage == 2)
            {
                NumberOfMessage = 0;
                String nounce = in.readUTF();
                Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
                SecretKeySpec secret_key = new SecretKeySpec(nounce.getBytes(), "HmacSHA256");
                sha256_HMAC.init(secret_key);
                SessionKey = sha256_HMAC.doFinal(message.getBytes());
                System.out.println("Session Key Changed !!!");
            }

            message = in.readUTF();
            Decrypted = Decryption(cipher, AESKey, IVV, message);
            System.out.println("Message from Server : " + Decrypted);
            NumberOfMessage++;
            if (Decrypted.equals("bye") || Decrypted.equals("Bye"))
                break;

            if (NumberOfMessage == 2)
            {
                NumberOfMessage = 0;
                String nounce = new BigInteger(512, new SecureRandom()).toString();
                out.writeUTF(nounce);
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

        SessionKey =  ServerPublic.modPow(PriKey, Prime).toString().getBytes();
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


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        Client client = new Client("127.0.0.1", 5000);
    }
    
}
