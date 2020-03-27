# Highly Dependable Systems

## Sistemas de Elevada Confiabilidade
### 2019-2020

#### Project - Stage 1
#### Dependable Public Announcement Server

***

## Functions

* **post(PublicKey key, char[255] message, int[] a)**

    Post a **message** to user's announcement board with **a** references.

    Input for function will be asked in terminal in this order:
    * Message (255 characters followed by enter) - Message to post
    * Announcement List (Numbers divided by comma. Ex: "1,2,3" or "1") - Posts to reference

* **postGeneral(PublicKey key, char[255] message, int[] a)**

    Post a **message** to the general board with **a** references.

    Input for function will be asked in terminal in this order:
    * Message (255 characters followed by enter) - Message to post
    * Announcement List (Numbers divided by comma. Ex: "1,2,3" or "1") - Posts to reference

* **read(PublicKey key, int number)**

    Read last **number** of messages from the announcement board associated with **key**.

    Input for function will be asked in terminal in this order:
    * Public Key (Input the complete name of the public key file clientPublicKeyX, where X is the Client number/id. Ex: clientPublicKey1) - Public key file associated with the announcement board to read
    * Number (A single number. Ex: 10) - Last X posts to read where X is the number input

* **readGeneral(int number)**

    Read last **number** of messages from the general board.

    Input for function will be asked in terminal in this order:
    * Number (A single number. Ex: 10) - Last X posts to read where X is the number input

***

# Explanation

This project needed to guarantee that the messages sent through unsecure channels had both integrity and non-repudiation.

Both the server and each client have RSA key pairs, with a public and private key, if its the first time the client or server are being ran a public and private RSA keys are generated and saved to keystore files.

These keys are used to sign the messages in order to guarantee integrity, and nonces are used to guarante protection against non-repudiation.

Whenever the server or the clients are sending messages to each other, they generate a 20 bytes Nonce from a [SecureRandom](https://docs.oracle.com/javase/7/docs/api/java/security/SecureRandom.html) random number generator, and creates a hash of the message with the nonce using a [MessageDigest](https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html) with SHA-1 Algorithm, and then using this hashed message as the input to create an RSA Signature also using SHA as the hash algorithm for the signature. The nonces are kept in a list of previous used nonces in order to guarantee it was actually only used once.

***

# Run 

### Run the Client

One terminal is needed for each Client, 10 clients will require 10 terminals.
Java Version 8 is needed.

To run client simply run `java Client X` where you replace X with the client ID, this will associate a keypair to each client.
Ex: `java Client 3` will associate the clientPublicKey3.key and  clientPrivateKey3 with this client.

A menu will appear with the possible command options, like this:

![Options Menu](https://github.com/BSantosCoding/SECProj/blob/master/readmeimg/secmenu.png)

### Run the Server

One terminal is needed for each Client, 10 clients will require 10 terminals.
Java Version 8 is needed.

To run server simply run `java Server` this will associate public_key.key and private_key.key with the server.
