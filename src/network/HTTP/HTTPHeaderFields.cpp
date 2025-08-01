#include "HTTPHeaderFields.h"

HTTPheaderFields::HTTPheaderFields()
{
    Index = 0;
}

bool HTTPheaderFields::_AddField(const char *Name, int NameSize, const char *Value, int ValueSize)
{
    if(Index < MAX_HTTP_HEADER_FIELDS)
    {
        //add name
        for (int i = 0; i < NameSize; i++) {
            Fields[Index].Name.push_back(std::tolower(static_cast<unsigned char>(Name[i])));
        }

        Fields[Index].Value.append(Value, ValueSize);
        Index++;
        return true;
    }
    return false;
}

const string HTTPheaderFields::GetFieldByName(const char *Name) const
{
    for (int i = 0; i < Index; ++i)
    {
        const std::string& fieldName = Fields[i].Name;

        int j = 0;
        while (j < fieldName.size() && Name[j]) {
            if (fieldName[j] != std::tolower(static_cast<unsigned char>(Name[j]))) {
                break;
            }
            ++j;
        }

        // equality
        if (j == fieldName.size() && Name[j] == '\0') {
            return Fields[i].Value;
        }
    }

    return {};  //return null
}

int16_t HTTPheaderFields::Count() const
{
    return Index;
}
