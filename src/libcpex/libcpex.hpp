#ifndef LIBCPEX_H
#define LIBCPEX_H

#include "includes/base.hpp"
#include "includes/http.hpp"
#include "includes/oprf.hpp"
#include "includes/cpexdht.hpp"
#include "includes/groupsig.hpp"
#include "includes/encryption.hpp"
#include "includes/secret_sharing.hpp"

namespace libcpex {
    void panic(string error);
    void print(string message);
    void printlist(vector<uint8_t> message);
    vector<uint8_t>GenerateCallId(string callDetails, vector<string> servers);
    void PublishMessage(vector<uint8_t>callId, vector<uint8_t>msg, vector<uint8_t>gsk);
    void RetrieveMessage(vector<uint8_t>callId, vector<uint8_t>gsk);
}

#endif // LIBCPEX_H
