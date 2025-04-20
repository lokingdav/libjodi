#include <stdexcept>
#include <mutex>
#include <chrono>
#include <condition_variable>
#include <thread>
#include "libjodi.hpp"  // Your existing .hpp with class definitions

namespace libjodi
{
//------------------------------------------------------------------------------
// OPRF IMPLEMENTATIONS
//------------------------------------------------------------------------------

OPRF_Keypair OPRF::Keygen()
{
    // Generate random secret scalar sk
    unsigned char sk[crypto_core_ristretto255_SCALARBYTES];
    randombytes_buf(sk, sizeof(sk));

    // pk = g^sk
    unsigned char pk[crypto_core_ristretto255_BYTES];
    crypto_scalarmult_ristretto255_base(pk, sk);

    OPRF_Keypair keypair;
    keypair.sk.assign(sk, sk + sizeof(sk));
    keypair.pk.assign(pk, pk + sizeof(pk));
    return keypair;
}

OPRF_Blinded OPRF::Blind(const std::string &msg)
{
    // 1. Hash message -> 64 bytes
    unsigned char hashbuf[64];
    crypto_hash_sha512(
        hashbuf,
        reinterpret_cast<const unsigned char*>(msg.data()),
        msg.size()
    );

    // 2. Convert that 64-byte hash to a Ristretto point
    unsigned char p_msg[crypto_core_ristretto255_BYTES];
    if (crypto_core_ristretto255_from_hash(p_msg, hashbuf) != 0) {
        throw std::runtime_error("crypto_core_ristretto255_from_hash() failed");
    }

    // 3. rand_scalar -> rand_point -> x = p_msg + rand_point
    unsigned char rand_scalar[crypto_core_ristretto255_SCALARBYTES];
    unsigned char rand_point[crypto_core_ristretto255_BYTES];
    unsigned char x[crypto_core_ristretto255_BYTES];

    crypto_core_ristretto255_scalar_random(rand_scalar);
    crypto_scalarmult_ristretto255_base(rand_point, rand_scalar);
    crypto_core_ristretto255_add(x, p_msg, rand_point);

    OPRF_Blinded out;
    out.x.assign(x, x + sizeof(x));
    out.r.assign(rand_scalar, rand_scalar + sizeof(rand_scalar));
    return out;
}

OPRF_BlindedEval OPRF::Evaluate(const OPRF_Keypair &keypair, const Bytes &x)
{
    if (x.size() != crypto_core_ristretto255_BYTES) {
        throw std::runtime_error("OPRF::Evaluate: invalid x size");
    }

    const unsigned char* skchar = keypair.sk.data();
    const unsigned char* xchar  = x.data();

    unsigned char fx[crypto_core_ristretto255_BYTES];
    if (crypto_scalarmult_ristretto255(fx, skchar, xchar) != 0) {
        throw std::runtime_error("crypto_scalarmult_ristretto255() failed in Evaluate()");
    }

    OPRF_BlindedEval out;
    out.fx.assign(fx, fx + sizeof(fx));
    out.vk = keypair.pk;  // store pubkey as verification key
    return out;
}

Bytes OPRF::Unblind(OPRF_BlindedEval eval, Bytes &sk)
{
    // Optional: check sizes
    if (eval.vk.size() != crypto_core_ristretto255_BYTES ||
        eval.fx.size() != crypto_core_ristretto255_BYTES ||
        sk.size()       != crypto_core_ristretto255_SCALARBYTES)
    {
        throw std::runtime_error("OPRF::Unblind: invalid input size");
    }

    const unsigned char* skchar = sk.data();
    const unsigned char* pkchar = eval.vk.data();
    const unsigned char* fxchar = eval.fx.data();

    // negative scalar
    unsigned char neg_sk[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_negate(neg_sk, skchar);

    // pk_neg_sk = pk^(neg_sk)
    unsigned char pk_neg_sk[crypto_core_ristretto255_BYTES];
    if (crypto_scalarmult_ristretto255(pk_neg_sk, neg_sk, pkchar) != 0) {
        throw std::runtime_error("crypto_scalarmult_ristretto255() failed in Unblind()");
    }

    // out = fx + pk_neg_sk
    unsigned char out[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_add(out, fxchar, pk_neg_sk);

    return Bytes(out, out + sizeof(out));
}

//------------------------------------------------------------------------------
// KEYROTATION IMPLEMENTATIONS
//------------------------------------------------------------------------------

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

bool KeyRotation::IsExpiredWithin(int index, int tmax)
{
    std::lock_guard<std::mutex> lock(sharedMutex);

    if (index < 0 || index >= (int)keyList.size()) {
        throw std::out_of_range("KeyRotation::IsExpiredWithin index out of range");
    }

    if (index != recentlyExpiredIndex) return false;

    auto currentTime = std::chrono::system_clock::now();
    auto thresholdTime = currentTime - std::chrono::seconds(tmax);

    return (recentlyExpiredTime >= thresholdTime);
}

KeyRotation::~KeyRotation()
{
    StopRotation();
}

OPRF_Keypair KeyRotation::GetKey(int index)
{
    std::lock_guard<std::mutex> lock(sharedMutex);
    if (index < 0 || index >= (int)keyList.size()) {
        throw std::out_of_range("KeyRotation::GetKey index out of range");
    }
    return keyList[index];
}

} // namespace libjodi
