#ifndef SECRET_SHARING_HPP
#define SECRET_SHARING_HPP

#include "base.hpp"

namespace libcpex {
    class SecretSharing {
        public:
            SecretSharing();
            static vector<Bytes> split(Bytes secret, int n, int t);
            static Bytes combine(vector<Bytes> shares);
    };
}

#endif // SECRET_SHARING_HPP
