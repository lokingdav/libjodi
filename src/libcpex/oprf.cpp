#include <sodium.h>
#include "libcpex.hpp"

namespace libcpex {
    void OPRF::InitSodium() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Sodium failed to init");
        }
    }

    OPRF_Keypair OPRF::Keygen() {
        OPRF::InitSodium();

        // generate random secret key
        unsigned char sk[crypto_core_ristretto255_SCALARBYTES];
        randombytes_buf(sk, sizeof sk);

        // Compute public key: pk = g^{sk}
        unsigned char pk[crypto_core_ristretto255_BYTES];
        crypto_scalarmult_ristretto255_base(pk, sk);

        return OPRF_Keypair(Bytes(sk, sk + sizeof sk), Bytes(pk, pk + sizeof pk));
    }

    OPRF_Blinded OPRF::Blind(const string* msg)
    {   OPRF::InitSodium();

        // Hash message to a point on the curve p_msg
        unsigned char p_msg[crypto_core_ristretto255_BYTES];
        crypto_core_ristretto255_from_hash(p_msg, reinterpret_cast<const unsigned char*>(msg->data()));

        // Blind point by  p_msg * g^r where g^r is a random point
        unsigned char rand_scalar[crypto_core_ristretto255_SCALARBYTES];
        unsigned char rand_point[crypto_core_ristretto255_BYTES];
        unsigned char x[crypto_core_ristretto255_BYTES];
        
        crypto_core_ristretto255_scalar_random(rand_scalar);
        crypto_scalarmult_ristretto255_base(rand_point, rand_scalar);
        crypto_core_ristretto255_add(x, p_msg, rand_point);

        OPRF_Blinded out;
        out.x = Bytes(x, x + sizeof x);
        out.r = Bytes(rand_scalar, rand_scalar + sizeof rand_scalar);
        return out;
    }

    OPRF_BlindedEval OPRF::Evaluate(const OPRF_Keypair& keypair, const Bytes& x) {
        OPRF::InitSodium();

        const unsigned char* skchar = keypair.sk.data();
        const unsigned char* xchar = x.data();

        // Compute f(x) = x^{sk}
        unsigned char fx[crypto_core_ristretto255_BYTES];
        if (crypto_scalarmult_ristretto255(fx, skchar, xchar) != 0) {
            panic("Failed to compute F(x)");
        }

        OPRF_BlindedEval out;
        out.fx = Bytes(fx, fx + sizeof fx);
        out.vk = keypair.pk;
        return out;
    }

    Bytes OPRF::Unblind(OPRF_BlindedEval eval, Bytes& sk) {
        OPRF::InitSodium();
        
        const unsigned char* skchar = sk.data();
        const unsigned char* pkchar = eval.vk.data();
        const unsigned char* fxchar = eval.fx.data();

        unsigned char neg_sk[crypto_core_ristretto255_SCALARBYTES];
        unsigned char pk_neg_sk[crypto_core_ristretto255_BYTES];

        crypto_core_ristretto255_scalar_negate(neg_sk, skchar);
        
        if (crypto_scalarmult_ristretto255(pk_neg_sk, neg_sk, pkchar) != 0) {
            panic("Executing crypto_scalarmult_ristretto255() failed");
        }

        unsigned char out[crypto_core_ristretto255_BYTES];
        crypto_core_ristretto255_add(out, fxchar, pk_neg_sk);

        return Bytes(out, out + sizeof out);
    }

    void KeyRotation::StartRotation(int size, int interval) {
        if (rotationRunning) return;

        expiryIndex = -1;
        recentlyExpiredIndex = -1;
        keyList.clear();

        for (auto i = 0; i < size; ++i) {
            keyList.push_back(OPRF::Keygen());
        }

        rotationRunning = true;
        stopRotation = false;

        std::thread([this, interval]() {
            while (!stopRotation) {
                std::this_thread::sleep_for(std::chrono::seconds(interval));

                if (stopRotation) break;

                std::lock_guard<std::mutex> lock(sharedMutex);
                //set current expiry index
                expiryIndex = (expiryIndex + 1) % keyList.size();
                // let current exppiryIndex be the recently expired
                recentlyExpiredIndex = expiryIndex;
                // let's keep the recently expired key
                recentlyExpiredKey = keyList[recentlyExpiredIndex];
                // let's replace the expired key
                keyList[expiryIndex] = OPRF::Keygen();
                // Remember the time recentlyExpiredIndex was replaced
                recentlyExpiredTime = std::chrono::system_clock::now();
            }

            rotationRunning = false;
        }).detach();
    }

    void KeyRotation::StopRotation() {
        if (!rotationRunning) return;

        stopRotation = true; // Signal the thread to stop

        // Wait briefly to ensure the thread finishes (optional, based on your use case)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Cleanup state
        expiryIndex = -1;
        keyList.clear();
    }

    bool KeyRotation::IsExpiredWithin(int index, int tmax) {
        if (index < 0) return false;
        
        if (index >= keyList.size()) {
            panic("index must be between 0 and size of keylist");
        }

        if (index != recentlyExpiredIndex) return false;

        auto currentTime = std::chrono::system_clock::now();
        auto thresholdTime = currentTime - std::chrono::seconds(tmax);

        return recentlyExpiredTime >= thresholdTime;
    }

    KeyRotation::~KeyRotation() { StopRotation(); }

    OPRF_Keypair KeyRotation::GetKey(int index) { 
        if (index < 0 || index >= keyList.size()) {
            panic("index must be between 0 and size of keylist");
        }
        return keyList[index];
    }
}