#ifndef PAIRING_HPP
#define PAIRING_HPP

#include "base.hpp"
#include "utils.hpp"
#include <mcl/bn256.hpp>

namespace libjodi {
    static void InitMCL()
    {
        mcl::bn::initPairing();
    }

    class PublicKey {
        static const int MAX_PK_SIZE = 128;

        public:
            mcl::bn::G2 GetG2() const {
                return v;
            }

            Bytes ToBytes() const {
                uint8_t buf[MAX_PK_SIZE];
                size_t len = v.serialize(buf, sizeof(buf));
                return Bytes(buf, buf + len);
            }

            string ToString() const {
                return Utils::EncodeBase64(ToBytes());
            }

            static PublicKey FromBytes(Bytes bytes) {
                PublicKey pk;
                pk.v.deserialize(bytes.data(), bytes.size());
                return pk;
            }

            static PublicKey FromString(string s) {
                Bytes bytes = Utils::DecodeBase64(s);
                return FromBytes(bytes);
            }

            static mcl::bn::G2 GetBase() {
                mcl::bn::G2 baseG2;
                mcl::bn::mapToG2(baseG2, 1);
                return baseG2;
            }

            PublicKey() {};
            PublicKey(mcl::bn::G2 v): v(v) {};

            bool operator==(const PublicKey& other) const {
                return v == other.v;
            }
        private:
            mcl::bn::G2 v;
    };

    class PrivateKey {
        static const int SK_SIZE = 32;

        public:
            PrivateKey() {};
            
            PrivateKey(mcl::bn::Fr s): s(s) {};

            Bytes ToBytes() const {
                uint8_t buf[SK_SIZE];
                size_t len = s.serialize(buf, sizeof(buf));
                return Bytes(buf, buf + len);
            }

            string ToString() const {
                return Utils::EncodeBase64(ToBytes());
            }

            static PrivateKey FromBytes(Bytes bytes) {
                PrivateKey sk;
                sk.s.deserialize(bytes.data(), bytes.size());
                return sk;
            }

            static PrivateKey FromString(string s) {
                Bytes bytes = Utils::DecodeBase64(s);
                return FromBytes(bytes);
            }

            static PrivateKey Keygen() {
                mcl::bn::Fr s;
                s.setRand();
                return PrivateKey(s);
            }

            PublicKey GetPublicKey() const {
                mcl::bn::G2 vk;
                mcl::bn::G2::mul(vk, PublicKey::GetBase(), s);
                return PublicKey(vk);
            }

            mcl::bn::Fr GetFr() const {
                return s;
            }

            PrivateKey Inverse() const {
                mcl::bn::Fr inv_s;
                mcl::bn::Fr::inv(inv_s, s);
                return PrivateKey(inv_s);
            }

            bool operator==(const PrivateKey& other) const {
                return s == other.s;
            }
        private:
            mcl::bn::Fr s;
    };

    class Point {
        static const int MAX_Pt_SIZE = 128;

        public:
            Point() {};

            Point(mcl::bn::G1 v): v(v) {};

            Bytes ToBytes() const {
                uint8_t buf[MAX_Pt_SIZE];
                size_t len = v.serialize(buf, sizeof(buf));
                return Bytes(buf, buf + len);
            }

            string ToString() const {
                return Utils::EncodeBase64(ToBytes());
            }

            static Point FromBytes(Bytes bytes) {
                Point p;
                p.v.deserialize(bytes.data(), bytes.size());
                return p;
            }

            static Point FromString(string s) {
                return FromBytes(Utils::DecodeBase64(s));
            }

            static Point HashToPoint(string m) {
                mcl::bn::Fp t;
                t.setHashOf(m);
                mcl::bn::G1 v;
                mcl::bn::mapToG1(v, t);
                return Point(v);
            }

            static Point Mul(const Point& p, const PrivateKey& sk) {
                mcl::bn::G1 v;
                mcl::bn::G1::mul(v, p.v, sk.GetFr());
                return Point(v);
            }

            mcl::bn::G1 GetG1() const {
                return v;
            }

            bool operator==(const Point& other) const {
                return v == other.v;
            }

            bool operator!=(const Point& other) const {
                return v != other.v;
            }
        private:
            mcl::bn::G1 v;
    };

    class Pairing {
        public:
            Pairing() {};

            Pairing(mcl::bn::Fp12 e): e(e) {};

            string ToString() const {
                return e.getStr();
            }

            static Pairing FromString(string s) {
                Pairing p;
                p.e.setStr(s);
                return p;
            }

            static Pairing Pair(const Point& x, const PublicKey& pk) {
                mcl::bn::Fp12 e;
                mcl::bn::pairing(e, x.GetG1(), pk.GetG2());
                return Pairing(e);
            }

            bool operator==(const Pairing& other) const {
                return e == other.e;
            }
        private:
            mcl::bn::Fp12 e;
    };
}

#endif // PAIRING_HPP