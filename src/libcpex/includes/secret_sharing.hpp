#ifndef SECRET_SHARING_HPP
#define SECRET_SHARING_HPP

#include "base.hpp"

namespace libcpex {
    class SecretSharing {
        public:
            SecretSharing();
            static vector<Bytes> split(vector<uint8_t>secret, int n, int t);
            static vector<uint8_t>combine(vector<Bytes> shares);
    };
}

#endif // SECRET_SHARING_HPP
