#ifndef HELPER_H
#define HELPER_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef ENABLE_SSL
    #include <openssl/ssl.h>
    #include <openssl/pem.h>
#endif

#include "sds.h"
#include "libircclient-include/strings_utils.h"
#include "xdccget.h"
#include "libircclient.h"
#include "hashmap.h"
#include "argument_parser.h"
#include "dirs.h"

#define LOG_ERR   0
#define LOG_QUIET 1
#define LOG_WARN  2
#define LOG_INFO  3


/* ansi color codes used at the dbg macros for coloured output. */

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

/* define DBG-macros for debugging purposes if DEBUG is defined...*/

#ifdef DEBUG
	#define DBG_MSG(color, stream, format, ...) do {\
		    fprintf(stream, "%sDBG:%s \"", color, KNRM);\
		    fprintf(stream, format, ##__VA_ARGS__);\
		    fprintf(stream, "\" function: %s file: %s line: %d\n",(char*) __func__, (char*)__FILE__, __LINE__);} while(0)
	
	#define DBG_OK(format, ...) do {\
				DBG_MSG(KGRN, stdout, format, ##__VA_ARGS__);\
		    } while(0)
	#define DBG_WARN(format, ...) do {\
				DBG_MSG(KYEL, stderr, format, ##__VA_ARGS__);\
		    } while(0)
	#define DBG_ERR(format, ...) do {\
		    	DBG_MSG(KRED, stderr, format, ##__VA_ARGS__);\
		    	exitPgm(EXIT_FAILURE);\
			} while(0)
#else
	#define DBG_MSG(color, stream, format, ...) do {} while(0)
	#define DBG_OK(format, ...) do {} while(0)
	#define DBG_WARN(format, ...) do {} while(0)
	#define DBG_ERR(format, ...) do {} while(0)
#endif

/* define macro for free that checks if ptr is null and sets ptr after free to null. */

#define FREE(X) \
do {\
	if ( (X != NULL) ) {\
		free(( X ));\
		X = NULL;\
	}\
} while(0)

#define bitset_t uint64_t

struct xdccGetConfig {
	int logLevel;
	char *ircServer;
	unsigned short port;
	int numChannels;
	sds *channelsToJoin;
	unsigned int numDownloads;
	struct dccDownload **dccDownloadArray;
	bool sended;
	irc_session_t *session;
	sds targetDir;
	char *args[3];
    bitset_t flags;
};

#define OUTPUT_FLAG             0x01
#define ALLOW_ALL_CERTS_FLAG    0x02
#define USE_IPV6_FLAG			0x03

struct terminalDimension {
	int rows;
	int cols;
};

struct checksumThreadData {
	sds completePath;
	sds expectedHash;
};

struct dccDownloadContext {
	struct dccDownloadProgress *progress;
	struct file_io_t *fd;
};

void cfg_clear_bit(struct xdccGetConfig *config, int bitNum);
void cfg_set_bit(struct xdccGetConfig *config, int bitNum);
int cfg_get_bit(struct xdccGetConfig *config, int bitNum);

void logprintf(int logLevel, char *formatString, ...);
/* Wrapper for malloc. Checks if malloc fails and exits pgm if it does. */
static inline void* Malloc(size_t size) {
    void *t = malloc(size);
    if (t == NULL)
    {
        logprintf(LOG_ERR, "malloc failed. exiting now.\n");
        exit(EXIT_FAILURE);
    }
    
    return t;
}
/* Mallocs and then nulls the reserved memory.  */
static inline void* Safe_Malloc(size_t size) {
    void *t = Malloc(size);
    memset(t, 0, size);
    return t;
}
/* wraps calloc call. */
static inline void* Calloc(size_t numElements, size_t sizeOfElement) {
    void *t = calloc(numElements, sizeOfElement);
    if (t == NULL)
    {
        logprintf(LOG_ERR, "calloc failed. exiting now.\n");
        exit(EXIT_FAILURE);
    }
    
    return t;
}

static inline sds getConfigDirectory() {
    sds configDir = sdscatprintf(sdsempty(), "%s%s%s%s", getHomeDir(), getPathSeperator(), ".xdccget", getPathSeperator());
    return configDir;
}

/* inits the rand-function */
void initRand();

/* reads in the complete content of an text file and returns sds string. string need to be freed with sdsfree*/
sds readTextFile (char *filePath);

/* range-based rand. the returned number will be at least low, but lower than high. */
int rand_range(int low, int high);

/* create a random nickname (e.g. a string) of nicklen chars. result is stored at nick.
   function does not malloc, so calling function has to reserve enough space at nick. */
void createRandomNick(int nickLen, char *nick);

struct terminalDimension *getTerminalDimension();

void printProgressBar(const int numBars, const double percentRdy);

int printSize (irc_dcc_size_t size);

void outputProgress(struct dccDownloadProgress *tdp);

#ifdef ENABLE_SSL
int openssl_check_certificate_callback(int preverify_ok, X509_STORE_CTX *ctx);
#endif

#endif
