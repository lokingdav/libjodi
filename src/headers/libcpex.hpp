#ifndef LIBCPEX_H
#define LIBCPEX_H

#include "http.hpp"
#include "oprf.hpp"
#include "cpexdht.hpp"
#include "groupsig.hpp"
#include "elements.hpp"
#include "encryption.hpp"
#include "secret_sharing.hpp"

namespace libcpex {
    void hello();

    Bytes GenerateCallId(string callDetails, vector<string> servers);
    void PublishMessage(Bytes callId, Bytes msg, Bytes gsk);
    void RetrieveMessage(Bytes callId, Bytes gsk);
}

#endif // LIBCPEX_H
