### How to run
This file could be run on Seed-lab VM. Instruction of how to setup the VM can be found on their official website.

To compile, run `g++ sample.cpp -o sample -std=c++11  -lcrypto`

To run the program, follow the command line and enter the corresponding IV and ciphertext in hex string. These two pairs together with the plaintext
must be encrypted with a key chosen from words.txt, using AES-128-CBC.
