#ifndef CLSHTTPHEADERFIELDS_H
#define CLSHTTPHEADERFIELDS_H
#define MAX_HTTP_HEADER_FIELDS (40)
#include <iostream>
#include <string.h>
using namespace std;

struct Content
{
    string Name;
    string Value;
};

class HTTPheaderFields
{
private:

    int16_t Index;
    Content Fields[MAX_HTTP_HEADER_FIELDS];

public:
    HTTPheaderFields();
    int16_t Count() const;
    const string GetFieldByName(const char *Name) const;
    bool _AddField(const char *Name, int NameSize, const char *Value, int ValueSize);
};


#endif // CLSHTTPHEADERFIELDS_H
