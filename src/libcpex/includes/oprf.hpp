#ifndef OPRF_HPP
#define OPRF_HPP

#include "base.hpp"
#include "includes/ec.hpp"

namespace libcpex {
    class OPRF {
        public:
            OPRF();
            Point Mask(string& msg, Scalar* out);
            vector<uint8_t>Evaluate(vector<uint8_t>key, vector<uint8_t>point);
            vector<uint8_t>Evaluate(Scalar key, vector<uint8_t>point);
    };
}

#endif // OPRF_HPP
