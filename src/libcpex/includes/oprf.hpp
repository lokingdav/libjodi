#ifndef OPRF_HPP
#define OPRF_HPP

#include <memory>
#include <random>
#include <chrono>
#include <mutex>

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
            Bytes x;
            Bytes r;
            OPRF_Blinded() {};
            OPRF_Blinded(Bytes x, Bytes r): r(r), x(x) {};
    };

    class OPRF_BlindedEval {
        public:
            Bytes fx;
            Bytes vk;
            OPRF_BlindedEval() {};
            OPRF_BlindedEval(Bytes fx, Bytes vk): fx(fx), vk(vk) {};
    };

    class OPRF {
        public:
            static void InitSodium();
            static OPRF_Keypair Keygen();
            static OPRF_Blinded Blind(const string* msg);
            static OPRF_BlindedEval Evaluate(const OPRF_Keypair& keypair, const Bytes& x);
            static Bytes Unblind(OPRF_BlindedEval eval, OPRF_Blinded& blinding);
            static Bytes Unblind(OPRF_BlindedEval eval, Bytes& r);
        
        private:
            OPRF() {};
    };

    class KeyRotation {
        public:
            ~KeyRotation();
            KeyRotation(KeyRotation const&) = delete;
            KeyRotation& operator=(KeyRotation const&) = delete;

            static std::shared_ptr<KeyRotation> GetInstance() {
                static std::shared_ptr<KeyRotation> s{new KeyRotation};
                return s;
            }

            bool IsExpiredWithin(int index, int tmax);
            void StartRotation(int size, int interval);
            void StopRotation();

            int GetExpiryIndex() { return expiryIndex; }
            int GetRecentlyExpiredIndex() { return recentlyExpiredIndex; }
            OPRF_Keypair GetRecentlyExpiredKey() { return recentlyExpiredKey; }

            OPRF_Keypair GetKey(int index);
            int GetListSize() { return keyList.size(); }
        private:
            int expiryIndex = -1;
            bool rotationRunning = false;
            bool stopRotation = false;

            int recentlyExpiredIndex = -1;
            OPRF_Keypair recentlyExpiredKey;
            std::chrono::time_point<std::chrono::system_clock> recentlyExpiredTime;

            vector<OPRF_Keypair> keyList;
            std::mutex sharedMutex;

            // Disable constructor to force singleton
            KeyRotation() {};
    };
}

#endif // OPRF_HPP
