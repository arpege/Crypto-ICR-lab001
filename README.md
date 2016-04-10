# ICR - labo 001

## Task 1

### Test suite for the server side
Make sure that all `.py` have execution privilege and python3 is installed on the machine. Run `chmod +x test_server.py && chmod +x server.py` to add privileges.

To run the server test suite :

1. start the server `./server.py`
2. run the test suite `./test_server.py`
 
Test case :

1. Legal message
2. Wrong timestamp
3. Wrong padding
4. Wrong MAC

Output :

```shell
Result expected : OK
[ANSWER IS: OK]

Result expected : WRONG TSP
[ANSWER IS: WRONG TSP]

Result expected : PADDING ERROR
[ANSWER IS: PADDING ERROR]

Result expected : MAC ERROR
[ANSWER IS: MAC ERROR]
```

### Test suite for the client side
Make sure that all `.py` and bash script have execution privilege and python3 is installed on the machine. Run `chmod +x test_client.py && chmod +x client.py` and `chmod +x run_client_test.sh` to add privileges.

The `test_client.py` file is a modified version of the regular server. This version send responses containing volunteers errors to test the reaction of the client. A bash script `run_client_test.sh` is used to make all client's calls.

To run the server test suite :

1. start the server `./test_client.py`
2. run the test suite `./run_client_test.sh`


Test case :

1. Correct response message
2. Incorrect response length 
3. Invalid response code
4. Invalid response timestamp
5. Incorrect response signature

Output :

```shell
[CORRECT RESPONSE EXPECTED]
[ANSWER IS: OK]

[INCORRECT LENGTH EXPECTED]
[ANSWER WITH INVALID LENGTH]

[INCORRECT CODE EXPECTED]
[ANSWER WITH INVALID CODE]

[INCORRECT TIMESTAMP EXPECTED]
[ANSWER WITH INVALID TIMESTAMP][TIMESTAMP = -1]

[INCORRECT MAC EXPECTED]
[ANSWER WITH WRONG MAC]
```

## Questions 1

### #1

**Which strategy is using SSH?** SSH use Encrypt-and-MAC

[Breaking and Provably Repairing the SSH Authenticated Encryption Scheme: A Case Study of the Encode-then-Encrypt-and-MAC Paradigm](http://homes.cs.washington.edu/~yoshi/papers/SSH/ssh.pdf)

**Which strategy is using TLS?** TLS use MAC-then-Encrypt strategie

[TLS Protocol Version 1.2](https://tools.ietf.org/html/rfc5246#section-6)

**Which one of the above three strategies is it recommended to use in practice?**

> ...theoretically "good" way is to apply the MAC on the encrypted data. This is called "encrypt-then-MAC". See this question on crypto.SE. As a summary, when you apply the MAC on the encrypted data, then whatever the MAC does cannot reveal anything on the plaintext data, and, similarly, since you verify the MAC before decrypting, then this will protect you against many chosen ciphertext attacks.

Source : [Combining MAC and Encryption](http://security.stackexchange.com/questions/26033/combining-mac-and-encryption)

### #2

**Instead of using a random IV, the CBC mode implements a nonce-based approach. What can you tell about its security?**

First, the "nonce IV" must be impredictable. If we use the current timestamp, it's broken. Second, it must not be the same twice nonce. With this method, we use only 8 bits, we have much less opportunity and arrive more quickly when the nonce will be repeated.

[Difference between a nonce and IV](http://crypto.stackexchange.com/questions/16000/difference-between-a-nonce-and-iv)

## Task 2

### #1

The original attack was published in 2002 by Serge Vaudenay. In 2010 the attack was applied to several web frameworks, including JavaServer Faces, Ruby on Rails and ASP.NET. In 2012 it was shown to be effective against some hardened security devices. A new variant, the Lucky Thirteen attack, published in 2013, used a timing side-channel to re-open the vulnerability even in implementations that had previously been fixed. As of early 2014, the attack is no longer considered a threat in real-life operation.

### #2

In the padding oracle attack, the client uses the server responses to determine if the padding of the cipher text sent is right. In this way, by changing the bits of the first block used by the CBC mode, the customer can gradually determined the intermediate state of the next block. The intermediate state in deciphering is after the secret key, but before the XOR with the previous block. Knowing the intermediate state and the cipher text of the previous block, we can retreave the clear text.

Source of inspiration : [The Padding Oracle Attack - why crypto is terrifying](http://robertheaton.com/2013/07/29/padding-oracle-attack/)

### #3



## Question 2