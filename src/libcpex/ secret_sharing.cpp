#include <vector>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <cassert>

extern "C" {
#include "../libs/sss/sss.h"
}
#include <sodium.h>

#include "libcpex.hpp"

namespace libcpex {
    vector<Bytes> SecretSharing::Split(Bytes const &secret, size_t n, size_t t) {
        if (n < t) panic("Number of shares (n) must be >= threshold (t).");
        if (secret.size() > sss_MLEN) panic("Secret is too long for sss library.");

        std::vector<uint8_t> secret_buf(sss_MLEN, 0);
        std::memcpy(secret_buf.data(), secret.data(), secret.size());

        std::vector<sss_Share> shares(n);
        sss_create_shares(shares.data(), secret_buf.data(), static_cast<uint8_t>(n), static_cast<uint8_t>(t));

        std::vector<Bytes> result;
        result.reserve(n);
        for (auto &sh : shares) {
            Bytes share(sh, sh + sss_SHARE_LEN);
            result.push_back(std::move(share));
        }

        return result;
    }

    Bytes SecretSharing::Combine(vector<Bytes> const & shares, size_t t) {
        if (shares.size() < t) panic("No shares provided.");

        for (auto const &share : shares) 
            if (share.size() != sss_SHARE_LEN) 
                panic("Invalid share size.");
        

        std::vector<sss_Share> sssShares(shares.size());
        for (size_t i = 0; i < shares.size(); ++i) {
            std::memcpy(sssShares[i], shares[i].data(), sss_SHARE_LEN);
        }

        std::vector<uint8_t> secret_buf(sss_MLEN, 0);

        int result = sss_combine_shares(secret_buf.data(), sssShares.data(), shares.size());

        if (result != 0) panic("Failed to combine shares to restore the secret.");
        Bytes sec(secret_buf.begin(), secret_buf.end());
        Bytes data = Utils::RemoveTrailingZeroes(sec);
        return data;
    }
}