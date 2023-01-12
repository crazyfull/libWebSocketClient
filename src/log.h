#ifndef LOGING_H
#define LOGING_H
#include <string.h>
#include <stdio.h>

    #ifdef NO_NEED_DEBUG
        #define DebugPrint(...) (void)0
    #else

        #define DEBUG_FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
        #define DebugPrint(...) do{ \
        printf("<%s::%s> ", DEBUG_FILE_NAME, __func__); \
        printf(__VA_ARGS__); \
        printf("\n");} while(0)
    #endif


    #ifdef NO_NEED_LOG
        #define LOG(...) (void)0
    #else
        #define LOG(...) do{ \
        printf(__VA_ARGS__); \
        printf("\n");} while(0);
    #endif

    #define ZERO (0)

    #ifdef ISINVALID
    #else
        #define ISINVALID (-1)
    #endif


#endif // LOGING_H
