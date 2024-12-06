#ifndef CPEX_DHT
#define CPEX_DHT

#include "base.hpp"
#include <vector>
#include <string>
#include <thread>
#include <mutex>

namespace libcpex {
    struct CpexNode {
        std::string id;
        std::string ipAddress;
        std::string baseUrl;
        bool isHealthy = false;
    };

    typedef std::vector<CpexNode> CpexNodes;

    class CpexDHT {
        public:
            // CpexDHT is a singleton class
            static CpexDHT& getInstance() {
                static CpexDHT instance;
                return instance;
            }

            CpexDHT(const CpexDHT&) = delete;
            CpexDHT& operator=(const CpexDHT&) = delete;

            std::vector<CpexNode> FindNodes(Bytes key, size_t count);
            void StartDiscovery(std::string url);
            void StopDiscovery();

        private:
            std::vector<CpexNode> nodes;
            bool discoveryRunning = false;
            bool stopDiscoveryFlag = false;
            std::thread discoveryThread;
            std::mutex nodesMutex; 
            std::string discoveryUrl;

            // Private constructor and destructor to enforce singletons
            CpexDHT();  
            ~CpexDHT();
    };
}

#endif // CPEX_DHT
