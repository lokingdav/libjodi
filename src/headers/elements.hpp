#ifndef ELEMENTS_HPP
#define ELEMENTS_HPP

#include "base.hpp"
#include <memory>
#include <openssl/ec.h>
#include <openssl/bn.h>

namespace libcpex {
    class G1 {
        public:
            G1();
            ~G1();

            // Copy Constructor and Assignment
            G1(const G1& other);
            G1& operator=(const G1& other);

            // Move Constructor and Assignment
            G1(G1&& other) noexcept;
            G1& operator=(G1&& other) noexcept;

            // Static Methods
            static G1 getGenerator();
            static BIGNUM* generateRandomScalar();
            static G1 hashToPoint(const std::string& data);

            // Member Methods
            G1 multiply(const BIGNUM* scalar) const;
            BIGNUM* inverseScalar(const BIGNUM* scalar) const;
            std::string toHex() const;
            void printCoordinates() const;

        private:
            EC_GROUP* group;
            EC_POINT* point;
            BN_CTX* ctx;

            // Helper Methods
            void initialize();
            void copyFrom(const G1& other);
            void clear();
    };
}

#endif // ELEMENTS_HPP
