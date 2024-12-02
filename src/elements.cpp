#include "libcpex.hpp"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <iostream>

namespace libcpex {

//////////////////////////
// Scalar Class Methods //
//////////////////////////

Scalar::Scalar() : bn_(BN_new()) {
    if (!bn_) throw std::runtime_error("Failed to create BIGNUM");
}

Scalar::~Scalar() {
    clear();
}

Scalar::Scalar(const Scalar& other) : bn_(BN_new()) {
    if (!bn_) throw std::runtime_error("Failed to create BIGNUM");
    copyFrom(other);
}

Scalar& Scalar::operator=(const Scalar& other) {
    if (this != &other) {
        clear();
        bn_ = BN_new();
        if (!bn_) throw std::runtime_error("Failed to create BIGNUM");
        copyFrom(other);
    }
    return *this;
}

Scalar::Scalar(Scalar&& other) noexcept : bn_(other.bn_) {
    other.bn_ = nullptr;
}

Scalar& Scalar::operator=(Scalar&& other) noexcept {
    if (this != &other) {
        clear();
        bn_ = other.bn_;
        other.bn_ = nullptr;
    }
    return *this;
}

void Scalar::initialize() {
    bn_ = BN_new();
    if (!bn_) throw std::runtime_error("Failed to create BIGNUM");
}

void Scalar::copyFrom(const Scalar& other) {
    if (BN_copy(bn_, other.bn_) == nullptr)
        throw std::runtime_error("Failed to copy BIGNUM");
}

void Scalar::clear() {
    if (bn_) {
        BN_clear_free(bn_);
        bn_ = nullptr;
    }
}

Scalar Scalar::generateRandomScalar() {
    Scalar scalar;
    BIGNUM* order = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    if (!order || !ctx)
        throw std::runtime_error("Failed to allocate resources");

    if (EC_GROUP_get_order(G1::getGroup(), order, ctx) != 1)
        throw std::runtime_error("Failed to get group order");

    if (BN_rand_range(scalar.bn_, order) != 1)
        throw std::runtime_error("Failed to generate random scalar");

    BN_free(order);
    BN_CTX_free(ctx);

    return scalar;
}

Scalar Scalar::fromHex(const std::string& hexStr) {
    Scalar scalar;
    if (BN_hex2bn(&scalar.bn_, hexStr.c_str()) == 0)
        throw std::runtime_error("Failed to create scalar from hex");
    return scalar;
}

Scalar Scalar::inverse() const {
    Scalar inv;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create BN_CTX");

    BIGNUM* order = BN_new();
    if (!order)
        throw std::runtime_error("Failed to create BIGNUM for order");

    if (EC_GROUP_get_order(G1::getGroup(), order, ctx) != 1)
        throw std::runtime_error("Failed to get group order");

    if (BN_mod_inverse(inv.bn_, bn_, order, ctx) == nullptr)
        throw std::runtime_error("Failed to compute inverse");

    BN_free(order);
    BN_CTX_free(ctx);

    return inv;
}

std::string Scalar::toHex() const {
    char* hexStr = BN_bn2hex(bn_);
    if (!hexStr) throw std::runtime_error("Failed to convert BIGNUM to hex");
    std::string result(hexStr);
    OPENSSL_free(hexStr);
    return result;
}

const BIGNUM* Scalar::getBn() const {
    return bn_;
}

///////////////////////
// G1 Class Methods //
///////////////////////

EC_GROUP* G1::getGroup() {
    static EC_GROUP* group = nullptr;
    if (!group) {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group) throw std::runtime_error("Failed to create EC_GROUP");
    }
    return group;
}

G1::G1() : point_(nullptr), ctx_(nullptr) {
    initialize();
}

G1::~G1() {
    clear();
}

void G1::initialize() {
    ctx_ = BN_CTX_new();
    if (!ctx_) throw std::runtime_error("Failed to create BN_CTX");

    point_ = EC_POINT_new(getGroup());
    if (!point_) throw std::runtime_error("Failed to create EC_POINT");
}

void G1::clear() {
    if (point_) {
        EC_POINT_free(point_);
        point_ = nullptr;
    }
    if (ctx_) {
        BN_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

G1::G1(const G1& other) {
    initialize();
    copyFrom(other);
}

G1& G1::operator=(const G1& other) {
    if (this != &other) {
        clear();
        initialize();
        copyFrom(other);
    }
    return *this;
}

G1::G1(G1&& other) noexcept
    : point_(other.point_), ctx_(other.ctx_) {
    other.point_ = nullptr;
    other.ctx_ = nullptr;
}

G1& G1::operator=(G1&& other) noexcept {
    if (this != &other) {
        clear();
        point_ = other.point_;
        ctx_ = other.ctx_;

        other.point_ = nullptr;
        other.ctx_ = nullptr;
    }
    return *this;
}

void G1::copyFrom(const G1& other) {
    if (EC_POINT_copy(point_, other.point_) != 1)
        throw std::runtime_error("Failed to copy EC_POINT");
}

G1 G1::getGenerator() {
    G1 gen;
    const EC_POINT* generator = EC_GROUP_get0_generator(getGroup());
    if (EC_POINT_copy(gen.point_, generator) != 1)
        throw std::runtime_error("Failed to get generator point");
    return gen;
}

G1 G1::hashToPoint(const std::string& data) {
    G1 point;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    BIGNUM* x = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, nullptr);
    if (!x) throw std::runtime_error("Failed to create BIGNUM from hash");

    // Try to find a valid point on the curve
    int y_bit = 0;
    while (true) {
        if (EC_POINT_set_compressed_coordinates_GFp(getGroup(), point.point_, x, y_bit, point.ctx_) == 1) {
            if (EC_POINT_is_on_curve(getGroup(), point.point_, point.ctx_) == 1) {
                break;
            }
        }
        // Increment x and try again
        if (BN_add_word(x, 1) != 1)
            throw std::runtime_error("Failed to increment BIGNUM");
    }

    BN_free(x);
    return point;
}

G1 G1::operator*(const Scalar& scalar) const {
    G1 result;
    if (EC_POINT_mul(getGroup(), result.point_, NULL, point_, scalar.getBn(), result.ctx_) != 1)
        throw std::runtime_error("Scalar multiplication failed");
    return result;
}


G1 G1::operator/(const Scalar& scalar) const {
    Scalar invScalar = scalar.inverse();
    return (*this) * invScalar;
}

std::string G1::toHex() const {
    char* hex = EC_POINT_point2hex(getGroup(), point_, POINT_CONVERSION_UNCOMPRESSED, ctx_);
    if (!hex) throw std::runtime_error("Failed to convert point to hex");
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

void G1::printCoordinates() const {
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    if (!x || !y) throw std::runtime_error("Failed to create BIGNUMs");
    if (EC_POINT_get_affine_coordinates_GFp(getGroup(), point_, x, y, ctx_) != 1)
        throw std::runtime_error("Failed to get point coordinates");
    char* x_hex = BN_bn2hex(x);
    char* y_hex = BN_bn2hex(y);
    std::cout << "X: " << x_hex << "\nY: " << y_hex << std::endl;
    OPENSSL_free(x_hex);
    OPENSSL_free(y_hex);
    BN_free(x);
    BN_free(y);
}

} // namespace libcpex
