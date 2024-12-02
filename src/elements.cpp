#include "elements.hpp"
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace libcpex {
    G1::G1() : group(nullptr), point(nullptr), ctx(nullptr) {
        initialize();
    }

    // Destructor
    G1::~G1() {
        clear();
    }

    // Copy Constructor
    G1::G1(const G1& other) : group(nullptr), point(nullptr), ctx(nullptr) {
        initialize();
        if (EC_POINT_copy(this->point, other.point) != 1) {
            throw std::runtime_error("Failed to copy EC_POINT");
        }
    }

    // Copy Assignment
    G1& G1::operator=(const G1& other) {
        if (this != &other) {
            if (EC_POINT_copy(this->point, other.point) != 1) {
                throw std::runtime_error("Failed to copy EC_POINT");
            }
        }
        return *this;
    }

    // Move Constructor
    G1::G1(G1&& other) noexcept : group(other.group), point(other.point), ctx(other.ctx) {
        other.group = nullptr;
        other.point = nullptr;
        other.ctx = nullptr;
    }

    // Move Assignment
    G1& G1::operator=(G1&& other) noexcept {
        if (this != &other) {
            clear();
            group = other.group;
            point = other.point;
            ctx = other.ctx;

            other.group = nullptr;
            other.point = nullptr;
            other.ctx = nullptr;
        }
        return *this;
    }

    // Initialize the EC_GROUP, EC_POINT, and BN_CTX
    void G1::initialize() {
        // Using secp256k1 curve
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (group == nullptr) {
            throw std::runtime_error("Failed to create EC_GROUP");
        }

        point = EC_POINT_new(group);
        if (point == nullptr) {
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to create EC_POINT");
        }

        ctx = BN_CTX_new();
        if (ctx == nullptr) {
            EC_POINT_free(point);
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to create BN_CTX");
        }
    }

    // Clear resources
    void G1::clear() {
        if (ctx) {
            BN_CTX_free(ctx);
            ctx = nullptr;
        }
        if (point) {
            EC_POINT_free(point);
            point = nullptr;
        }
        if (group) {
            EC_GROUP_free(group);
            group = nullptr;
        }
    }

    // Static Method: Get Generator
    G1 G1::getGenerator() {
        G1 generator;
        if (EC_POINT_copy(generator.point, EC_GROUP_get0_generator(generator.group)) != 1) {
            throw std::runtime_error("Failed to copy generator point");
        }
        return generator;
    }

    // Static Method: Generate Random Scalar
    BIGNUM* G1::generateRandomScalar() {
        BIGNUM* scalar = BN_new();
        if (scalar == nullptr) {
            throw std::runtime_error("Failed to allocate BIGNUM for scalar");
        }

        // Using secp256k1 order
        const EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (group == nullptr) {
            BN_free(scalar);
            throw std::runtime_error("Failed to create EC_GROUP for scalar generation");
        }

        BIGNUM* order = BN_new();
        if (order == nullptr) {
            EC_GROUP_free(group);
            BN_free(scalar);
            throw std::runtime_error("Failed to allocate BIGNUM for group order");
        }

        if (EC_GROUP_get_order(group, order, nullptr) != 1) {
            EC_GROUP_free(group);
            BN_free(order);
            BN_free(scalar);
            throw std::runtime_error("Failed to get group order");
        }

        // Generate random scalar in [1, order-1]
        if (BN_rand_range(scalar, order) != 1) {
            EC_GROUP_free(group);
            BN_free(order);
            BN_free(scalar);
            throw std::runtime_error("Failed to generate random scalar");
        }

        // Ensure scalar is not zero
        while (BN_is_zero(scalar)) {
            if (BN_rand_range(scalar, order) != 1) {
                EC_GROUP_free(group);
                BN_free(order);
                BN_free(scalar);
                throw std::runtime_error("Failed to generate non-zero scalar");
            }
        }

        EC_GROUP_free(group);
        BN_free(order);
        return scalar;
    }

    // Static Method: Hash to Point (Simple Try-and-Increment)
    G1 G1::hashToPoint(const std::string& data) {
        G1 result;
        unsigned int counter = 0;
        unsigned char hash_output[SHA256_DIGEST_LENGTH];
        std::vector<unsigned char> concatenated_data;

        while (true) {
            // Concatenate data with counter
            concatenated_data.assign(data.begin(), data.end());
            concatenated_data.push_back(static_cast<unsigned char>(counter));

            // Compute SHA-256 hash
            SHA256(concatenated_data.data(), concatenated_data.size(), hash_output);

            // Convert hash to BIGNUM
            BIGNUM* x = BN_bin2bn(hash_output, SHA256_DIGEST_LENGTH, nullptr);
            if (x == nullptr) {
                throw std::runtime_error("Failed to convert hash to BIGNUM");
            }

            // Attempt to create a valid point with x-coordinate
            if (EC_POINT_set_compressed_coordinates_GFp(result.group, result.point, x, 1, result.ctx) == 1) {
                BN_free(x);
                // Verify the point is on the curve
                if (EC_POINT_is_on_curve(result.group, result.point, result.ctx) == 1) {
                    break; // Successfully found a valid point
                }
            }

            BN_free(x);
            counter++;
            if (counter == 256) {
                throw std::runtime_error("Failed to hash to point after 256 attempts");
            }
        }

        return result;
    }

    // Member Method: Multiply Point by Scalar
    G1 G1::multiply(const BIGNUM* scalar) const {
        G1 result;
        if (EC_POINT_mul(result.group, result.point, nullptr, this->point, scalar, result.ctx) != 1) {
            throw std::runtime_error("Failed to multiply point by scalar");
        }
        return result;
    }

    // Member Method: Inverse of Scalar modulo Group Order
    BIGNUM* G1::inverseScalar(const BIGNUM* scalar) const {
        BIGNUM* inverse = BN_new();
        if (inverse == nullptr) {
            throw std::runtime_error("Failed to allocate BIGNUM for inverse");
        }

        // Get group order
        BIGNUM* order = BN_new();
        if (order == nullptr) {
            BN_free(inverse);
            throw std::runtime_error("Failed to allocate BIGNUM for group order");
        }

        if (EC_GROUP_get_order(this->group, order, this->ctx) != 1) {
            BN_free(order);
            BN_free(inverse);
            throw std::runtime_error("Failed to get group order");
        }

        // Compute inverse: inverse = scalar^{-1} mod order
        if (BN_mod_inverse(inverse, scalar, order, this->ctx) == nullptr) {
            BN_free(order);
            BN_free(inverse);
            throw std::runtime_error("Failed to compute inverse of scalar");
        }

        BN_free(order);
        return inverse;
    }

    // Member Method: Serialize Point to Hex String (Uncompressed)
    std::string G1::toHex() const {
        char* hex = EC_POINT_point2hex(this->group, this->point, POINT_CONVERSION_UNCOMPRESSED, this->ctx);
        if (hex == nullptr) {
            throw std::runtime_error("Failed to serialize point to hex");
        }
        std::string hex_str(hex);
        OPENSSL_free(hex);
        return hex_str;
    }

    // Member Method: Print Coordinates
    void G1::printCoordinates() const {
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        if (x == nullptr || y == nullptr) {
            BN_free(x);
            BN_free(y);
            throw std::runtime_error("Failed to allocate BIGNUMs for coordinates");
        }

        if (EC_POINT_get_affine_coordinates_GFp(this->group, this->point, x, y, this->ctx) != 1) {
            BN_free(x);
            BN_free(y);
            throw std::runtime_error("Failed to get affine coordinates");
        }

        char* x_hex = BN_bn2hex(x);
        char* y_hex = BN_bn2hex(y);
        if (x_hex && y_hex) {
            std::cout << "Point Coordinates:\n";
            std::cout << "X: " << x_hex << "\nY: " << y_hex << std::endl;
        }

        OPENSSL_free(x_hex);
        OPENSSL_free(y_hex);
        BN_free(x);
        BN_free(y);
    }
}
