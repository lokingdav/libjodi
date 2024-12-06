#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include "base.hpp"

namespace libcpex {
    class Encryption {
        public:
            Encryption();
            static Bytes Keygen();
            static Bytes Encrypt(const Bytes &key, const Bytes &plaintext);
            static Bytes Decrypt(const Bytes &key, const Bytes &ciphertext);
    };
}

#endif // ENCRYPTION_HPP
