#ifndef HTTP_HPP
#define HTTP_HPP

#include "base.hpp"
#include <map>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using namespace nlohmann;

namespace libcpex {
    struct Request {
        std::string endpoint;
        std::map<std::string, std::string> body;
        std::map<std::string, std::string> headers;
    };

    struct Response {
        bool success;
        int statusCode;
        std::string errorMessage;
        std::map<std::string, std::string> headers;
        json payload;
    };

    class Http {
    public:
        static std::vector<Response> gets(const std::vector<Request>& requests);
        static std::vector<Response> posts(const std::vector<Request>& requests);

        static Response get(const Request& req);
        static Response post(const Request& req);

    private:
        static Response performHttpRequest(const Request& req, bool isPost);
    };
}

#endif // HTTP_HPP
