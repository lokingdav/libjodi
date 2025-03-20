#include "voprf.hpp"

namespace libcpex {
    VOPRF_Blinded VOPRF::Blind(const std::string &msg) {
        mcl::bn::initPairing();

        VOPRF_Blinded blinded;
        blinded.r = PrivateKey::Keygen();
        blinded.x = Point::Mul(Point::HashToPoint(msg), blinded.r);
        return blinded;
    }

    Point VOPRF::Unblind(const Point& fx, const PrivateKey& r) {
        mcl::bn::initPairing();
        return Point::Mul(fx, r.Inverse());
    }

    Point VOPRF::Evaluate(const PrivateKey& sk, const Point& x) {
        mcl::bn::initPairing();
        return Point::Mul(x, sk);
    }

    bool VOPRF::Verify(const PublicKey& pk, const Point& x, const Point& fx) {
        mcl::bn::initPairing();
        Pairing e1 = Pairing::Pair(x, pk);
        Pairing e2 = Pairing::Pair(fx, PublicKey::GetBase());
        return e1 == e2;
    }
} // namespace libcpex