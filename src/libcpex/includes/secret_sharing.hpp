#ifndef SECRET_SHARING_HPP
#define SECRET_SHARING_HPP

#include "base.hpp"

namespace libcpex {
    class SecretSharing {
        public:
            SecretSharing();
            static vector<Bytes> Split(Bytes const &secret, size_t n, size_t t);
            static Bytes Combine(vector<Bytes> const & shares, size_t t);
    };
}

#endif // SECRET_SHARING_HPP
