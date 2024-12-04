#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include "base.hpp"

namespace libcpex {
    class Encryption {
        public:
            Encryption();
            Bytes encrypt(Bytes msg, Bytes callId);
            Bytes decrypt(Bytes ctx, Bytes callId, Bytes key);
    };
}

#endif // ENCRYPTION_HPP
