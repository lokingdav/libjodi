#ifndef SECRET_SHARING_HPP
#define SECRET_SHARING_HPP

#include "base.hpp"

namespace libcpex {
    class SecretSharing {
        public:
            SecretSharing();
            static vector<Bytes> Split(Bytes const &secret, size_t n = 5, size_t t = 3);
            static Bytes Combine(vector<Bytes> const & shares, size_t t = 3);
    };
}

#endif // SECRET_SHARING_HPP
