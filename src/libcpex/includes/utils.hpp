#ifndef CPEX_UTILS_HPP
#define CPEX_UTILS_HPP

#include "base.hpp"

namespace libcpex {
    class Utils {
        public:
            Utils();
            static string BytesToString(Bytes const & data);
            static Bytes StringToBytes(string const & data);

            static Bytes Sha160(Bytes const & preimage);
            static Bytes Sha256(Bytes const & preimage);

            static string EncodeBase64(Bytes const & data);
            static Bytes DecodeBase64(string const & data);

            static Bytes Xor(Bytes const & x, Bytes const & y);
            static Bytes RemoveTrailingZeroes(Bytes & data);
    };
}

#endif // CPEX_UTILS_HPP
