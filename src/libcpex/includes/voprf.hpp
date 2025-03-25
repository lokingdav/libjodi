#ifndef VOPRF_HPP
#define VOPRF_HPP

#include "base.hpp"
#include "pairing.hpp"

namespace libcpex {
    class VOPRF_Blinded {
        public:
            PrivateKey r;
            Point x;

            VOPRF_Blinded() {};
            VOPRF_Blinded(PrivateKey r, Point x): r(r), x(x) {};
            VOPRF_Blinded(Point x, PrivateKey r): x(x), r(r) {};
    };

    class VOPRF {
        public:
            static VOPRF_Blinded Blind(const string &msg);

            static Point Unblind(const Point& fx, const PrivateKey& r);

            static Point Evaluate(const PrivateKey& sk, const Point& x);
            static bool Verify(const PublicKey& pk, const string& x, const Point& fx);
        
        private:
            VOPRF() {};
    };
}

#endif // VOPRF_HPP