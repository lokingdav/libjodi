#ifndef OPRF_HPP
#define OPRF_HPP

#include "base.hpp"

namespace libcpex {
    class ObliviousPRF {
        public:
            ObliviousPRF();
            Bytes evaluate(Bytes key, Bytes x);
    };
}

#endif // OPRF_HPP
