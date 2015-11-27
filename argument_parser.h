#ifndef ARGUMENT_PARSER_H
#define ARGUMENT_PARSER_H

#include "sds.h"
#include "helper.h"

struct dccDownload {
    sds botNick;
    sds xdccCmd;
};

struct dccDownloadProgress {
    unsigned long key;
    irc_dcc_size_t completeFileSize;
    irc_dcc_size_t sizeRcvd;
    irc_dcc_size_t sizeNow;
    irc_dcc_size_t sizeLast;
    sds completePath;
};

void parseArguments(int argc, char **argv, struct xdccGetConfig *args);

struct dccDownload* newDccDownload(char *botNick, char *xdccCmd);

void freeDccDownload(struct dccDownload *t);

struct dccDownloadProgress* newDccProgress(char *filename, irc_dcc_size_t complFileSize);

void freeDccProgress(struct dccDownloadProgress *progress);

void parseDccDownload (char *dccDownloadString, char **nick, char **xdccCmd);

sds* parseChannels(char *channelString, int *numChannels);

struct dccDownload** parseDccDownloads(char *dccDownloadString, unsigned int *numDownloads);

#endif
