# Communication through Unsecure Channel !!!

##### This is Client Server code sending message with Confidentiality and Integrity through Unsecure Channel .
##### Here we soppose that Attackers can see the code and have access to our files so we can not save our key in a file or hardcode it . I have seprated code to the three main steps below:


  - Generate private and public parameters for keyexchange with DHKE algorithm to Exchange Session key
  - Using AES-256 bit Key to Encrypt/Decrypt messages (Confidentiality)
  - Using HMAC-SHA256 Signing the messages (Integrity)

#### Step 1:
First of all Use openssl tools to generate (Prime and Generator) parameters of DHEK protocol. here for more secure against brute-force attack I have used 2048 bit Prime number:

```
 openssl dhparam -out dhp.pem 2048
 openssl pkeyparam -in dhp.pem -text
```
after this both Client and Server send thier Publick Key to another side and both calculate Common Key according to DH algorithm.at last use SHA256 hash function to create 256bit Session key from Common Key from previous section.

#### Step 2:
Here I have used Java Socket programming for creating channel for communication between Client and Server.In all sections we suppose that this channel is unsecure and Attacker can see messages over channel. So for Cofidentiality of messages we Encrypt messages with AES-256 bit with CBC Encryptin mode with InitialVector = 0 . Because of Security of AES256 bit Key Confidentiality of messages are guaranteed against brute-force attacks.

#### Step 3:
With AES ecnryption we just guarantee Confidentiality of masseges so for Integrity we use SHA256 hash functin and concatenate the hash of message to end of the message and then encrypt it and because just client and server have Session key so messages are authenticated. also because of ussing Session key for authentication we can not provide non-repudiation. so in recieving side after decrypting message we seprate 256 bit of the end of the message as hash of message and recompute hash of message and compare it with value we expect . if there is problem proper message will be show to the client or server.

#### Key Freshness :
For more security of messages and prevnting attacker from having large number of Ciphers with the same Session key after every 5 messages between Client and server Session Key is refreshed. we do this by HMAC-SHA256. one of sides generate random value called "nounce" and send it to other side. both client and server use output of hmac for the nounce with previuos Session key as hmac key.

##### note that for simplicity of code first client is connected to server and send server a message and then server reply the message to the client and this will be repeated til one of sides send "Bye" message to other side.
##### In every message transfering Encrypted message is showed in sending side and Decrypted message in recieving side. and every time that key changes Client and Server will be noticed with a message.




