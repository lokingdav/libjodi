#include <sodium.h>
#include "libjodi.hpp"

namespace libjodi {
    Bytes Ciphering::Keygen() {
        Bytes key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        crypto_aead_xchacha20poly1305_ietf_keygen(key.data());
        return key;
    }

    Bytes Ciphering::Encrypt(const Bytes &key, const Bytes &plaintext) {
        if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            panic("Invalid key size.");
        }

        Bytes nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(nonce.data(), nonce.size());

        Bytes ctx(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

        unsigned long long ctx_len;

        const unsigned char *ad = NULL;
        size_t ad_len = 0;

        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                ctx.data(), &ctx_len,
                plaintext.data(), plaintext.size(),
                ad, ad_len,
                NULL, // no secret nonce
                nonce.data(), key.data()) != 0) {
            panic("Encryption failed.");
        }

        ctx.resize(ctx_len);
        nonce.insert(nonce.end(), ctx.begin(), ctx.end());
        return nonce;
    }

    Bytes Ciphering::Decrypt(const Bytes &key, const Bytes &ciphertext) {
        if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            panic("Invalid key size.");
        }

        if (ciphertext.size() <= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
            panic("Invalid Ciphertext");
        }

        Bytes nonce(ciphertext.begin(), ciphertext.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        Bytes ctx(ciphertext.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, ciphertext.end());

        if (ctx.empty()) {
            panic("Null ciphertext");
        }

        Bytes plaintext(ctx.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);

        unsigned long long plaintext_len;
        const unsigned char *ad = NULL;
        size_t ad_len = 0;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext.data(), &plaintext_len,
                NULL, // no secret nonce
                ctx.data(), ctx.size(),
                ad, ad_len,
                nonce.data(), key.data()) != 0) {
            panic("Decryption failed. Invalid ciphertext or key.");
        }

        plaintext.resize(plaintext_len);
        
        return plaintext;
    }
}