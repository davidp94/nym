# Tenderming Interactions

## Notice:

This document is outdated and does not represent the workings of the current version of the system. It is going to be updated at later date.

Both alternatives assume user already has an 'account' on the blockchain with some funds available on it. For the sake of simplicity, let's assume his public key is also the account address or the address can be directly derived from the key.

## Alternative A:

(Optional) 0. User obtains some specific credential from an identity provider

### == ISSUANCE ==

1. User sends a request to some node on the blockchain to transfer its funds to the pipe account. The request contains the following:
- public key
- value (according to some set with allowed values)
- random nonce 
- signature on the message
I've included the nonce to prevent replay attacks since without it any malicious entity could in theory take the message and send it multiple times to the blockchain to make user transfer all its funds to the pipe account. Alternatively Tendermint could disallow sending same message twice to the blockchain but then the user could only obtain a token of the particular value once per epoch.

The response the user receives contains the height of the block with the transaction.

2. User sends request to each IA for the partial credential. Each request contains the following:
- value (has to be identical to the one transfered to pipe account)
- height of the blockchain with the transaction from previous step
- user's ElGamal Public key (does it have to be fresh for each request or can it be persistent?)
- Encryption of random sequence number and encryption of user's private key (even though it is never revealed, does the key have to be different from the original pair used to identify the user, i.e. the same one used for user's account?)
- Proofs of correctness of the above encryptions
- signature on the message 

3. IAs do the usual verification of request + store the nonce from the blockchain transaction. I could not think of a better way to prevent reusing the transaction in this design flow apart from IAs having local cache of them. I think 'Alternative B' is better in this regard, but has different issues.

4. User unblinds the credentials, aggregates them + randomises.

### == SPENDING == 

5. User sends the credential to merchant to spend it. The message has the following: 
- credential
- value of the credential
- sequence number s or g^s (since I don't think that revealing s itself would cause any linkability (it was never revealed before), is there any point in not doing it?)
- proof of knowledge of the private key; the proof is binded to the merchant's address

6. Merchant submits the message to the blockchain and the value from the pipe account is transferred to the merchant. Now, in your paper you say that user directly sends sequence number s to the merchant, however, merchant itself submits g^s (and proof correct formation) to blockchain. Is there a reason for this? Why couldn't the merchant simply use plain s it was provided with. And then s could be used for checking for double spending rather than g^s.

## Alternative B:

(Optional) 0. User obtains some specific credential from an identity provider

### == ISSUANCE ==

1. User sends request to each IA for the partial credential. Each request contains the following:
- value
- user's ElGamal Public key (does it have to be fresh for each request or can it be persistent?)
- Encryption of random sequence number and encryption of user's private key (even though it is never revealed, does the key have to be different from the original pair used to identify the user, i.e. the same one used for user's account?)
- Proofs of correctness of the above encryptions
- signature on the message

2. Each IA would try to send request to the blockchain to transfer the value from user's account to the pipe account. Only one would succeed, the rest would have to be ignored as being duplicate. This solves the issue of having nonces in requests and IAs having to cache them, but now instead there's going to be up to (n-1) invalid transactions to blockchain for each new credential issuance. Each IA returns partial credential to the user (assuming all verification went fine)

3. User unblinds the credentials, aggregates them + randomises.

4. Spending is identical to Alternative A