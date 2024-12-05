#ifndef OPRF_HPP
#define OPRF_HPP

#include "base.hpp"

namespace libcpex {
    class OPRF_Keypair {
        public:
            Bytes sk;
            Bytes pk;
            OPRF_Keypair() {};
            OPRF_Keypair(Bytes sk, Bytes pk): sk(sk), pk(pk) {};
    };

    class OPRF_Blinded {
        public:
            Bytes mask;
            Bytes sk;
            OPRF_Blinded() {};
            OPRF_Blinded(Bytes msk, Bytes rs): mask(msk), sk(rs) {};
    };

    class OPRF_BlindedEval {
        public:
            Bytes fx;
            Bytes pk;
            OPRF_BlindedEval() {};
            OPRF_BlindedEval(Bytes fx, Bytes pk): fx(fx), pk(pk) {};
    };

    class OPRF {
        public:
            OPRF();

            static void InitSodium();
            static OPRF_Keypair Keygen();
            static OPRF_Blinded Blind(const string* msg);
            static OPRF_BlindedEval Evaluate(const OPRF_Keypair& keypair, const Bytes& x);
            static Bytes Unblind(OPRF_BlindedEval eval, OPRF_Blinded& blinding);
            static Bytes Unblind(OPRF_BlindedEval eval, Bytes& sk);
    };
}

#endif // OPRF_HPP
