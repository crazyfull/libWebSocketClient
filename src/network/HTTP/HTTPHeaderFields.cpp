#include "HTTPHeaderFields.h"

HTTPheaderFields::HTTPheaderFields()
{
    Index = 0;
}

bool HTTPheaderFields::_AddField(const char *Name, int NameSize, const char *Value, int ValueSize)
{
    if(Index < MAX_HTTP_HEADER_FIELDS)
    {
        Fields[Index].Name.append(Name, NameSize);
        Fields[Index].Value.append(Value, ValueSize);
        Index++;
        return true;
    }
    return false;
}

const string HTTPheaderFields::GetFieldByName(const char *Name) const
{
    string ret;
    for (int i = 0; i < Index; ++i)
    {
        if(Fields[i].Name == Name)
        {
            ret = Fields[i].Value;
        }
    }
    return ret;
}

int16_t HTTPheaderFields::Count() const
{
    return Index;
}
