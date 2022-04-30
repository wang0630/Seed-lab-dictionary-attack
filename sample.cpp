/* Reference: https://github.com/saju/misc/blob/master/misc/openssl_aes.c */
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>

using namespace std;

struct ResultCipher {
    unsigned char* buffer;
    int totalWrittenBufferLen;
};

/* Test sample 1:
 * iv = "aabbccddeeff00998877665544332211"
 * cipher text: "764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2"
 * answer: Syracuse
 *
 * Test sample 2:
 * iv = "010203040506070809000a0b0c0d0e0f"
 * cipher text: "e5accdb667e8e569b1b34f423508c15422631198454e104ceb658f5918800c22"
 * answer: example
 * */


class CipherPair {
  private:
    EVP_CIPHER_CTX* en{};
    unsigned char* plaintext = (unsigned char *) "This is a top secret.";
    unsigned char iv[16];
    unsigned char ciphertext[32];

    ResultCipher aesEncrypt(const unsigned char* key) {
        int f_len = 0;
        // Length of the plain text, in this case is 21 bytes long
        int plaintext_len = strlen((char*)this->plaintext);

        // length of the cipher text
        // The length of the cipher text is at most plaintext + one block size - 1
        // Since if plaintext is 17 bytes(one byte more), we need 17 + 16(block size) - 1 = 32 bytes
        int c_len = plaintext_len + AES_BLOCK_SIZE - 1;
        cout << "key: " << key << endl;
        cout << "cipher: " << this->ciphertext << endl;
        cout << "plaintext_len: " << plaintext_len << endl;
        cout << "ciphertext len: " << sizeof(this->ciphertext) << endl;
        cout << "c_len: " << c_len << endl;

        // Buffer to store final ciphertext
        auto outBuffer = (unsigned char *) (malloc(c_len));
        memset(outBuffer, 0, c_len);

        unsigned char keyWithPadding[16];
        memset(keyWithPadding, 0, 16);

        // If key is less than 16 bytes, pad #(0x23) to the end
        if (strlen((char*)key) < 16) {
            int i = strlen((char*)key);
            memcpy(keyWithPadding, key, i);
            while (i < 16) {
                keyWithPadding[i] = 0x23;
                ++i;
            }
        }

        cout << "Init keyWithPadding: " << keyWithPadding << endl;

        EVP_EncryptInit_ex(en, EVP_aes_128_cbc(), NULL, keyWithPadding, this->iv);

        OPENSSL_assert(EVP_CIPHER_CTX_key_length(en) == 16);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(en) == 16);

        /* update ciphertext, outBuffer will be filled with encrypted data
         * writtenBufferLen will be how many bytes is written into outBuffer */
        int totalWrittenBufferLen = 0;
        int writtenBufferLen = 0;
        EVP_EncryptUpdate(en, outBuffer, &writtenBufferLen, this->plaintext, plaintext_len);
        cout << "write first " << writtenBufferLen << " bytes" << endl;
        totalWrittenBufferLen += writtenBufferLen;
        cout << "First outBuffer:" << endl;
        this->printHex(outBuffer, writtenBufferLen);

        /* Update ciphertext with the final remaining bytes
         * Which means the last block
         * The last block will contain padding algorithm
         *
         * From official document:
         * If padding is enabled (the default) then EVP_EncryptFinal_ex()
         * encrypts the "final" data, that is any data that remains in a partial block
         * outBuffer should have enough spaces for one more block.
         *
         * outBuffer+writtenBufferLen means that we move the array ptr to
         * where the empty spaces begins(we already wrote writtenBufferLen bytes).
         * */
        EVP_EncryptFinal_ex(en, outBuffer+writtenBufferLen, &writtenBufferLen);
        totalWrittenBufferLen += writtenBufferLen;
        cout << "write second " << writtenBufferLen << " bytes" << endl;
        cout << "totalWrittenBufferLen: " << totalWrittenBufferLen << endl;

        return ResultCipher {
            outBuffer, totalWrittenBufferLen
        };
    }

    void printHex(unsigned char* test, int size) {
        for (int i = 0; i < size; i++) {
            if (i == size/2) printf("\n");
            printf("%.2x", test[i]);
        }
        cout << endl;
    }

    void hexString2Char(char* s, unsigned char* buff) {
        for (int i = 0, j = 0; i < strlen(s); i = i + 2, j++) {
            char p[2];
            memcpy(p, s + i, 2);
            // Convert hex string "7b" to one byte number 118
            // and assign to unsigned char
            unsigned char k = strtol(p, nullptr, 16);
            buff[j] = k;
        }
    }

  public:
    CipherPair(char* ciphertext, char* iv) {
        en = EVP_CIPHER_CTX_new();

        // Convert given hex string to actual unsigned char array
        this->hexString2Char(ciphertext, this->ciphertext);
        this->printHex(this->ciphertext, sizeof(this->ciphertext));

        this->hexString2Char(iv, this->iv);
        this->printHex(this->iv, sizeof(this->iv));
    }

    bool isKeyFound(string& key) {
        ResultCipher candidateCipher = this->aesEncrypt((unsigned char *) key.c_str());

        cout <<  "Original Cipher: " << endl;
        this->printHex(this->ciphertext, sizeof(this->ciphertext));
        cout << endl;

        cout << "Final outBuffer len: " << candidateCipher.totalWrittenBufferLen << endl;
        cout <<  "Final outBuffer: " << endl;
        this->printHex(candidateCipher.buffer, candidateCipher.totalWrittenBufferLen);
        cout << endl;

        if (candidateCipher.totalWrittenBufferLen <= 0) {
            cout << "The key " << key << " has ciphertext length 0" << endl;
            return false;
        } else if (candidateCipher.totalWrittenBufferLen != sizeof(this->ciphertext)) {
            cout << "The key " << key << " has ciphertext length " << candidateCipher.totalWrittenBufferLen << endl;
            return false;
        }

        bool isFound = true;
        for (int i = 0; i < candidateCipher.totalWrittenBufferLen; i++) {
            if (candidateCipher.buffer[i] != this->ciphertext[i]) {
                isFound = false;
                break;
            }
        }

        free(candidateCipher.buffer);

        if (isFound) {
            cout << "Great! key found: \"" << key << "\"\n";
            return true;
        }
        else {
            cout << "FAIL for \"" << key << "\"\n";
            return false;
        }
    }

    void clean() {
        // Clean up Cipher ctx object
        EVP_CIPHER_CTX_cleanup(this->en);
    }
};

int main(int argc, char* argv[])
{
    int lineLimit = 0;
    string cipherText, iv;
    cout << "Enter line limit: " << endl;
    cin >> lineLimit;
    cout << "Enter Cipher: " << endl;
    cin >> cipherText;
    cout << "Enter iv: " << endl;
    cin >> iv;
//    return 0;
    // read word from dictionary
    string dictionaryPath = "./words.txt";

    ifstream dictionary (dictionaryPath.c_str());


    string word;
    int i = lineLimit;
    if (dictionary.is_open()) {
        while (getline(dictionary, word)) {
            if (i == 0) break;
            auto cipherPair = new CipherPair((char*)cipherText.c_str(), (char*)iv.c_str());
            cout << "Start: " << word << '\n';
            if (cipherPair->isKeyFound(word)) {
                cout << "Succeed" << '\n';
                cipherPair->clean();
                return 0;
            } else {
                cout << endl << endl;
            }
            cipherPair->clean();
            i--;
        }
        dictionary.close();
    }
}
