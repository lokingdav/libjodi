#ifndef LIBJODI_H
#define LIBJODI_H

#include "includes/base.hpp"
#include "includes/http.hpp"
#include "includes/oprf.hpp"
#include "includes/pairing.hpp"
#include "includes/voprf.hpp"
#include "includes/utils.hpp"
#include "includes/dht.hpp"
#include "includes/groupsig.hpp"
#include "includes/ciphering.hpp"

namespace libjodi {
    void panic(string error);
    void print(string message);
    void printlist(vector<uint8_t> message);
    void printBytes(Bytes b);
    vector<uint8_t>GenerateCallId(string callDetails, vector<string> servers);
    void PublishMessage(vector<uint8_t>callId, vector<uint8_t>msg, vector<uint8_t>gsk);
    void RetrieveMessage(vector<uint8_t>callId, vector<uint8_t>gsk);
}

#endif // LIBJODI_H
