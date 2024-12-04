#include <openssl/rand.h>
#include "libcpex.hpp"

namespace libcpex {
    void Scalar::CheckKeyData() const {
        if (this->sdata == nullptr) {
            throw std::runtime_error(
                "PrivateKey::CheckKeyData keydata not initialized");
        }
    }
    
    Scalar Scalar::Random() {
        Bytes seed(Scalar::SIZE);

        if (RAND_bytes(seed.data(), Scalar::SIZE) != 1) {
            throw std::runtime_error("Cant generate seed for Scalar");
        }

        return Scalar::Deserialize(seed);
    }

    Bytes Scalar::Serialize() {
        this->CheckKeyData();
        vector<uint8_t> data(Scalar::SIZE);
        blst_bendian_from_scalar(data.data(), this->sdata);
        return data;
    }

    Scalar Scalar::Deserialize(Bytes data) {
        Scalar s;
        blst_scalar_from_bendian(s.sdata, data.data());
        return s;
    }

    Scalar Scalar::Inverse() {
        Scalar scalar;
        blst_sk_inverse(scalar.sdata, this->sdata);
        return scalar;
    }

    bool operator==(const Scalar& s1, const Scalar &s2) {
        s1.CheckKeyData();
        s2.CheckKeyData();
        return memcmp(s1.sdata, s2.sdata, sizeof(blst_scalar)) == 0;
    }

    blst_scalar Scalar::GetScalarData() {
        return *this->sdata;
    }

    Point Point::HashToPoint(Bytes message) {
        Point point;
        point.p = G1Element::FromMessage(message, message.data(), message.size());
        return point;
    }

    Point Point::HashToPoint(string message) {
        Bytes msg(message.begin(), message.end());
        return Point::HashToPoint(msg);
    }

    Bytes Point::Serialize() {
        return this->p.Serialize();
    }

    Point Point::Deserialize(Bytes data)
    {
        Point point(G1Element::FromBytes(data));

        return point;
    }

    G1Element Point::GetPointData() {
        return this->p;
    }

    Point operator*(Scalar& scalar, Point& point) {
        Point ans(scalar.GetScalarData() * point.GetPointData());
        return ans;
    }

    Point operator*(const Point& point, const Scalar &scalar) {
        return scalar * point;
    }
} // namespace libcpex
