#include "sodium/randombytes.h"
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
        randombytes_buf(seed.data(), Scalar::SIZE);
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
        this->CheckKeyData();
        blst_sk_inverse(scalar.sdata, this->sdata);
        return scalar;
    }

    bool operator==(const Scalar& s1, const Scalar &s2) {
        s1.CheckKeyData();
        s2.CheckKeyData();
        return memcmp(s1.sdata, s2.sdata, sizeof(blst_scalar)) == 0;
    }

    blst_scalar Scalar::GetScalarData() const {
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

    G1Element Point::GetElement() const {
        return this->p;
    }

    Point operator*(const Scalar& scalar, const Point& point) {
        Point ans(scalar.GetScalarData() * point.GetElement());
        return ans;
    }

    Point operator*(const Point& point, const Scalar &scalar) {
        return scalar * point;
    }

    void Point::CheckValid() const {
        this->p.CheckValid();
    }

    bool operator==(const Point &p1, const Point &p2) {
        p1.CheckValid();
        p2.CheckValid();
        return p1.GetElement() == p2.GetElement();
    }

} // namespace libcpex
