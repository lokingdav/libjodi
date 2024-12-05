#include <sodium.h>
#include <chrono>

const int numIters = 1000;

int main(int argc, char* argv[])
{
    if (sodium_init() < 0) {
        // Panic! The library couldn't be initialized, it is not safe to use
        return -1;
    }
    
    // -------- First party -------- Send blinded p(x)
    unsigned char x[crypto_core_ristretto255_HASHBYTES];
    randombytes_buf(x, sizeof x);

    // Compute px = p(x), a group element derived from x
    unsigned char px[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_from_hash(px, x);

    // Compute a = p(x) * g^r
    unsigned char r[crypto_core_ristretto255_SCALARBYTES];
    unsigned char gr[crypto_core_ristretto255_BYTES];
    unsigned char a[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(gr, r);
    crypto_core_ristretto255_add(a, px, gr);

    // -------- Second party -------- Send g^k and a^k
    unsigned char k[crypto_core_ristretto255_SCALARBYTES];
    randombytes_buf(k, sizeof k);

    // Compute v = g^k
    unsigned char v[crypto_core_ristretto255_BYTES];
    crypto_scalarmult_ristretto255_base(v, k);

    // Compute b = a^k
    unsigned char b[crypto_core_ristretto255_BYTES];
    if (crypto_scalarmult_ristretto255(b, k, a) != 0) {
        return -1;
    }

    // -------- First party -------- Unblind f(x)
    // Compute vir = v^(-r)
    unsigned char ir[crypto_core_ristretto255_SCALARBYTES];
    unsigned char vir[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_scalar_negate(ir, r);
    crypto_scalarmult_ristretto255(vir, ir, v);

    // Compute f(x) = b * v^(-r) = (p(x) * g^r)^k * (g^k)^(-r)
    //              = (p(x) * g)^k * g^(-k) = p(x)^k
    unsigned char fx[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_add(fx, b, vir);
    
    return 0;
}