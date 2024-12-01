#ifndef LIBCPEX_H
#define LIBCPEX_H

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <map>
#include <curl/curl.h>

using std::string;
using std::vector;
using std::map;
using std::thread;

namespace libcpex {
    typedef vector<uint8_t> Bytes;
    struct CpexNode {
        string id;
        string ipAddress;
        string baseUrl;
        bool isHealthy = false;
    };
    struct Request {
        string url;
        string payload;
        map<string, string> headers;
    };
    typedef vector<CpexNode> CpexNodes;

    class CpexDHT;
    class MessageStore;
    class MessageRetriever;
    class MessagePublisher;

    class Http;
    class Protocol;
    class Groupsig;
    class Encryption;
    class ObliviousPRF;
    class SecretSharing;


    void hello();

    class Http {
        public:
            Http();
            ~Http();

            vector<string> get(const vector<Request>& requests);
            vector<string> post(const vector<Request>& requests);

        private:
            void performGetRequest(const Request& req, string& response);
            void performPostRequest(const Request& req, string& response);

            static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
        };


    class CpexDHT {
        private:
            CpexNodes nodes;

        public:
            CpexDHT();
            CpexDHT(CpexNodes nodes);

            void Listen(string publicRegistryUrl);
            CpexNodes FindNodes(string key, int replication_params = 3);
            CpexNodes FindNodes(Bytes key, int replication_params = 3);
            CpexNode Ping(string key);
            CpexNode Ping(Bytes key);
    };

    class Encryption {
        public:
            Encryption();
            Bytes encrypt(Bytes msg, Bytes callId);
            Bytes decrypt(Bytes ctx, Bytes callId, Bytes key);
    };

    class SecretSharing {
        public:
            SecretSharing();
            static vector<Bytes> split(Bytes secret, int n, int t);
            static Bytes combine(vector<Bytes> shares);
    };

    class ObliviousPRF {
        public:
            ObliviousPRF();
            Bytes evaluate(Bytes key, Bytes x);
    };

    class Groupsig {
        public:
            Groupsig();
            Bytes sign(Bytes sk, Bytes msg);
            bool verify(Bytes pk, Bytes signature, Bytes msg);
    };

    class Protocol {
        public:
            Protocol();
            Bytes GenerateCallId(string callDetails, vector<string> servers);
            void Publish(Bytes callId, Bytes msg, Bytes gsk);
            void Retrieve(Bytes callId, Bytes gsk);
    };
}

#endif // LIBCPEX_H
