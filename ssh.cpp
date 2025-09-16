#include <sodium.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>

std::string hexify(const unsigned char *buf, size_t len) {
    // Takes bytes and turns them into 16-base num
    std::ostringstream oss;
    oss << std::hex << std::setfill('0'); // So all the ints will take 2 spaces

    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << (int)buf[i];
    }

    return oss.str();
}

int main() {
    if (sodium_init() < 0) {
        std::cout << "Libsodium init failed\n";
        return 1;
    }

    std::cout << "Initialsiation OK\n";

    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];

    // Generating keys with X25519
    crypto_kx_keypair(client_pk, client_sk); 
    crypto_kx_keypair(server_pk, server_sk);

    std::cout << "Private keys generated: \n";
    std::cout << "Client PK: " << hexify(client_pk, sizeof client_pk) << "\n";
    std::cout << "Server PK: " << hexify(server_pk, sizeof server_pk) << "\n";

    unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], client_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES], server_tx[crypto_kx_SESSIONKEYBYTES];

    // client computes keys using its keypair and the server's public key:
    if (crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk) != 0) {
        std::cout << "client key derivation failed\n";
        return 1;
    }

    // server does analogous computation (note parameter order: server_pk, server_sk, client_pk)
    if (crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk) != 0) {
        std::cout << "server key derivation failed\n";
        return 1;
    }

    // On this step client and server got shared keys (client tx is server rx and vice versa)
    std::cout << "\n" << "Transmission keys derived:\n";
    std::cout << "client_tx: " << hexify(client_tx, sizeof client_tx) << "\n";
    std::cout << "server_rx: " << hexify(server_rx, sizeof server_rx) << "\n";
    std::cout << "server_tx: " << hexify(server_tx, sizeof server_tx) << "\n";
    std::cout << "client_rx: " << hexify(client_rx, sizeof client_rx) << "\n"; 

    // Check if server tx equals client rx and vice versa
    if (sodium_memcmp(client_tx, server_rx, crypto_kx_SESSIONKEYBYTES) == 0)
        std::cout << "[OK] client_tx == server_rx\n";
    else
        std::cout << "[!] mismatch\n";

    if (sodium_memcmp(client_rx, server_tx, crypto_kx_SESSIONKEYBYTES) == 0)
        std::cout << "[OK] client_rx == server_tx\n";
    else
        std::cout << "[!] mismatch\n";

    std::string message;

    std::cout << "Transfer your message: ";
    std::getline(std::cin, message);

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // allocate ciphertext. It'll contain the message + MAC tag (extra 16 bytes)
    std::vector<unsigned char> ciphertext(message.size() + crypto_aead_chacha20poly1305_IETF_ABYTES);
    unsigned long long clen = 0;

    // ChaCha20 encrypting the message. ChaCha20 is symmetrical, but since client_tx equals to server_rx, 
    // we can act like if they both had the same key from now on (well this is sort of the case)
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &clen,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        nullptr, 0,    // additional data (AAD) - would be used in real-life communication
        nullptr,       // nsec (not used)
        nonce,
        client_tx
    );

    std::cout << "\n" << "nonce: " << hexify(nonce, sizeof nonce) << "\n";
    std::cout << "Client said: " << hexify(ciphertext.data(), clen) << "\n";

    // Now we decrypt it on the server
    std::vector<unsigned char> recovered(message.size()); // space for plaintext
    unsigned long long rlen = 0;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            recovered.data(), &rlen,
            nullptr,
            ciphertext.data(), clen,
            nullptr, 0,
            nonce,
            server_rx) != 0) {
        std::cerr << "Decryption failed: authentication failed!\n";
        return 1;
    }
    std::string recovered_str(reinterpret_cast<char*>(recovered.data()), rlen);
    std::cout << "Server heard: " << recovered_str << "\n";

    return 0;
}