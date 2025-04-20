#ifndef CIPHERING_HPP
#define CIPHERING_HPP

#include "base.hpp"

namespace libjodi {
    class Ciphering {
        public:
            Ciphering();
            static Bytes Keygen();
            static Bytes Encrypt(const Bytes &key, const Bytes &plaintext);
            static Bytes Decrypt(const Bytes &key, const Bytes &ciphertext);
    };
}

#endif // CIPHERING_HPP
