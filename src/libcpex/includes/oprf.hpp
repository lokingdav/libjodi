#ifndef OPRF_HPP
#define OPRF_HPP

#include <memory>
#include <random>
#include <chrono>

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
            static void InitSodium();
            static OPRF_Keypair Keygen();
            static OPRF_Blinded Blind(const string* msg);
            static OPRF_BlindedEval Evaluate(const OPRF_Keypair& keypair, const Bytes& x);
            static Bytes Unblind(OPRF_BlindedEval eval, OPRF_Blinded& blinding);
            static Bytes Unblind(OPRF_BlindedEval eval, Bytes& sk);
        
        private:
            OPRF() {};
    };

    class KeyRotation {
        public:
            ~KeyRotation();
            KeyRotation(KeyRotation const&) = delete;
            KeyRotation& operator=(KeyRotation const&) = delete;

            static std::shared_ptr<KeyRotation> getInstance() {
                static std::shared_ptr<KeyRotation> s{new KeyRotation};
                return s;
            }

            bool IsExpiredWithin(size_t index, size_t tmax);
            void StartRotation(size_t size, size_t interval);
            void StopRotation();
        private:
            size_t expiryIndex = -1;
            bool rotationRunning = false;
            bool stopRotation = false;

            size_t recentlyExpiredIndex = -1;
            OPRF_Keypair recentlyExpiredKey;
            std::chrono::time_point<std::chrono::system_clock> recentlyExpiredTime;

            vector<OPRF_Keypair> keyList;

            // Disable constructor to force singleton
            KeyRotation() {};
    };
}

#endif // OPRF_HPP
