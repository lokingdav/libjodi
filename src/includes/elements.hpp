#ifndef ELEMENTS_HPP
#define ELEMENTS_HPP

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <memory>

namespace libcpex {

class Scalar {
public:
    Scalar();
    Scalar(const Scalar& other);
    Scalar& operator=(const Scalar& other);
    Scalar(Scalar&& other) noexcept;
    Scalar& operator=(Scalar&& other) noexcept;
    ~Scalar();

    // Static Methods
    static Scalar generateRandomScalar();
    static Scalar fromHex(const std::string& hexStr);

    // Member Methods
    Scalar inverse() const;
    std::string toHex() const;

    // **Added**: Public accessor for bn_
    const BIGNUM* getBn() const;

private:
    BIGNUM* bn_;

    // Helper Methods
    void initialize();
    void copyFrom(const Scalar& other);
    void clear();
};

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
    static G1 hashToPoint(const std::string& data);

    // Static method to access shared group
    static EC_GROUP* getGroup();

    // Operator Overloading
    G1 operator*(const Scalar& scalar) const;
    G1 operator/(const Scalar& scalar) const;

    // Member Methods
    std::string toHex() const;
    void printCoordinates() const;

private:
    EC_POINT* point_;
    BN_CTX* ctx_;

    // Helper Methods
    void initialize();
    void copyFrom(const G1& other);
    void clear();
};

} // namespace libcpex

#endif // ELEMENTS_HPP
