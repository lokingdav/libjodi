#ifndef OPRF_HPP
#define OPRF_HPP

#include "base.hpp"
#include "includes/ec.hpp"

namespace libcpex {
    class OPRF {
        public:
            OPRF();
            Point Mask(string& msg, Scalar* out);
            Bytes Evaluate(Bytes key, Bytes point);
            Bytes Evaluate(Scalar key, Bytes point);
    };
}

#endif // OPRF_HPP
