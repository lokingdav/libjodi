#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include "base.hpp"

namespace libcpex {
    class Encryption {
        public:
            Encryption();
            vector<uint8_t>encrypt(vector<uint8_t>msg, vector<uint8_t>callId);
            vector<uint8_t>decrypt(vector<uint8_t>ctx, vector<uint8_t>callId, vector<uint8_t>key);
    };
}

#endif // ENCRYPTION_HPP
