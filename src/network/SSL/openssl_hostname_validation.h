//#include "openssl/types.h"
#include "openssl/x509v3.h"

typedef enum {
        MatchFound,
        MatchNotFound,
        NoSANPresent,
        MalformedCertificate,
        Error
} HostnameValidationResult;


HostnameValidationResult validate_hostname(const char *hostname, const X509 *server_cert);
