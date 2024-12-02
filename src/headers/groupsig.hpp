#ifndef CPEX_GROUPSIG_HPP
#define CPEX_GROUPSIG_HPP

#include "base.hpp"

namespace libcpex {
    class Groupsig {
        public:
            Groupsig();
            Bytes sign(Bytes sk, Bytes msg);
            bool verify(Bytes pk, Bytes signature, Bytes msg);
    };
}

#endif // CPEX_GROUPSIG_HPP
