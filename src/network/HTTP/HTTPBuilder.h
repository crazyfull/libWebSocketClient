#ifndef HTTPBUILDER_H
#define HTTPBUILDER_H

#include "HTTPClient.h"
#include <iostream>
#include <string.h>
using namespace std;

class HTTPBuilder
{
public:
    HTTPBuilder();
    static string GenerateGETRequest(const URL &url);
private:
    static string generateKey();
};

#endif // HTTPBUILDER_H
