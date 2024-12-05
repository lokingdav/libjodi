#ifndef HTTP_HPP
#define HTTP_HPP

#include "base.hpp"
#include <thread>
#include <curl/curl.h>

using std::thread;

namespace libcpex {
    struct Request {
        string url;
        string payload;
        map<string, string> headers;
    };

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
}

#endif // HTTP_HPP
