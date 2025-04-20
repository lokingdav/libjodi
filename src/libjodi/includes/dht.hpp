#ifndef JODI_DHT
#define JODI_DHT

#include "base.hpp"
#include <vector>
#include <string>
#include <thread>
#include <mutex>

namespace libjodi {
    struct JodiNode {
        std::string id;
        std::string baseUrl;
        bool isHealthy = false;
    };

    typedef std::vector<JodiNode> JodiNodes;

    class JodiDHT {
        public:
            // JodiDHT is a singleton class
            static JodiDHT& getInstance() {
                static JodiDHT instance;
                return instance;
            }

            JodiDHT(const JodiDHT&) = delete;
            JodiDHT& operator=(const JodiDHT&) = delete;

            std::vector<JodiNode> FindNodes(Bytes key, size_t count);
            void StartDiscovery(std::string url);
            void StopDiscovery();

        private:
            std::vector<JodiNode> nodes;
            bool discoveryRunning = false;
            bool stopDiscoveryFlag = false;
            std::thread discoveryThread;
            std::mutex nodesMutex; 
            std::string discoveryUrl;

            // Private constructor and destructor to enforce singletons
            JodiDHT();  
            ~JodiDHT();
    };
}

#endif // JODI_DHT
