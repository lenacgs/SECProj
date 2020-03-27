# Highly Dependable Systems

## Sistemas de Elevada Confiabilidade
### 2019-2020

#### Project - Stage 1
#### Dependable Public Announcement Server

***

## Functions

* **post(PublicKey key, char[255] message, int[] a)**

    Input for function will be asked in terminal in this order:
    * Message (255 characters followed by enter) - Message to post
    * Announcement List (Numbers divided by comma. Ex: "1,2,3" or "1") - Posts to reference

* **postGeneral(PublicKey key, char[255] message, int[] a)**

    Input for function will be asked in terminal in this order:
    * Message (255 characters followed by enter) - Message to post
    * Announcement List (Numbers divided by comma. Ex: "1,2,3" or "1") - Posts to reference

* **read(PublicKey key, int number)**

    Input for function will be asked in terminal in this order:
    * Public Key (Input the complete name of the public key file clientPublicKeyX, where X is the Client number/id. Ex: clientPublicKey1) - Public key file associated with the announcement board to read
    * Number (A single number. Ex: 10) - Last X posts to read where X is the number input

* **readGeneral(int number)**

    Input for function will be asked in terminal in this order:
    * Number (A single number. Ex: 10) - Last X posts to read where X is the number input
