#ifndef CPEX_GROUPSIG_HPP
#define CPEX_GROUPSIG_HPP

#include "base.hpp"

namespace libcpex {
    class Groupsig {
        public:
            Groupsig();
            vector<uint8_t>sign(vector<uint8_t>sk, vector<uint8_t>msg);
            bool verify(vector<uint8_t>pk, vector<uint8_t>signature, vector<uint8_t>msg);
    };
}

#endif // CPEX_GROUPSIG_HPP
