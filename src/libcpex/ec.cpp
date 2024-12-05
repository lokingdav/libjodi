#include "sodium.h"
#include "libcpex.hpp"

namespace libcpex {
    Scalar Scalar::Random() {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium failed to initialize");
        }
        vector<uint8_t> seed(Scalar::SIZE);
        for (auto i = 0; i < Scalar::SIZE; i++) {
            seed[i] = static_cast<uint8_t>(randombytes_uniform(256));
        }
        return Scalar::Deserialize(seed);
    }

    vector<uint8_t>Scalar::Serialize() {
        return this->sdata.Serialize();
    }

    Scalar Scalar::Deserialize(vector<uint8_t>data) {
        Scalar s(PrivateKey::FromBytes(data, true));
        return s;
    }

    Scalar Scalar::Inverse() {
        // serialize private key into bytes
        vector<uint8_t>keydata = sdata.Serialize();

        //import blst_scalar from bytes
        blst_scalar* bs = Util::SecAlloc<blst_scalar>(1);
        blst_scalar_from_bendian(bs, keydata.data());

        // inverse the blst_scalar
        blst_scalar* ret = Util::SecAlloc<blst_scalar>(1);
        blst_sk_inverse(ret, bs);

        // free initial blst_scalar
        Util::SecFree(bs);

        // convert ret to vector<uint8_t>then to private key object
        blst_bendian_from_scalar(keydata.data(), ret);
        Scalar scalar(PrivateKey::FromBytes(keydata));
        return scalar;
    }

    bool operator==(const Scalar& s1, const Scalar &s2) {
        return s1.sdata == s2.sdata;
    }

    PrivateKey Scalar::GetScalarData() const {
        return this->sdata;
    }

    Point Point::HashToPoint(vector<uint8_t>message) {
        Point point(
            G1Element::FromMessage(message, message.data(), message.size())
        );
        return point;
    }

    Point Point::HashToPoint(string message) {
        vector<uint8_t>msg(message.begin(), message.end());
        return Point::HashToPoint(msg);
    }

    vector<uint8_t>Point::Serialize() {
        return this->p.Serialize();
    }

    Point Point::Deserialize(vector<uint8_t>data)
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
