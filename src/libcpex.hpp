#ifndef LIBCPEX_H
#define LIBCPEX_H

#include "includes/http.hpp"
#include "includes/oprf.hpp"
#include "includes/cpexdht.hpp"
#include "includes/groupsig.hpp"
#include "includes/ec.hpp"
#include "includes/encryption.hpp"
#include "includes/secret_sharing.hpp"

namespace libcpex {
    void hello();

    Bytes GenerateCallId(string callDetails, vector<string> servers);
    void PublishMessage(Bytes callId, Bytes msg, Bytes gsk);
    void RetrieveMessage(Bytes callId, Bytes gsk);
}

#endif // LIBCPEX_H
