/*
	xdccget -- download files from xdcc via cmd line
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <inttypes.h>

#include "helper.h"
#include "file.h"
#include "hashing_algo.h"
#include "config.h"

#define NICKLEN 20

static struct xdccGetConfig cfg;

unsigned int downloadNumber = 0;
unsigned int finishedDownloads = 0;
struct dccDownloadContext **downloadContext = NULL;
struct dccDownloadProgress *lastDownload = NULL;
struct dccDownloadProgress *curDownload = NULL;

struct xdccGetConfig *getCfg() {
    return &cfg;
}

void doCleanUp() {
#ifndef WINDOWS_BUILD 
    int i;
    if (cfg.session)
        irc_destroy_session(cfg.session);

    for (i = 0; i < cfg.numChannels; i++) {
        sdsfree(cfg.channelsToJoin[i]);
    }

    for (i = 0; cfg.dccDownloadArray[i]; i++) {
        freeDccDownload(cfg.dccDownloadArray[i]);
    }
    
    for (i = 0; downloadContext[i]; i++) {
        struct dccDownloadContext *current_context = downloadContext[i];
        struct dccDownloadProgress *current_progress = current_context->progress;
        
        if (current_progress != NULL) {
            bool finishedDownloading = current_progress->sizeRcvd == current_progress->completeFileSize;

            if (!finishedDownloading) {
                Close(current_context->fd);
                current_context->fd = NULL;
            }

            freeDccProgress(current_context->progress);
        }
        
        FREE(downloadContext[i]);
    }

    sdsfree(cfg.targetDir);
    FREE(cfg.dccDownloadArray);
    FREE(cfg.channelsToJoin);
    FREE(downloadContext);
#endif
}

void exitPgm(int retCode) {
    doCleanUp();
    exit(retCode);
}

void interrupt_handler(int signum) {
    if (cfg.session && irc_is_connected(cfg.session)) {
        irc_cmd_quit(cfg.session, "Goodbye!");
    }
    else {
        exitPgm(0);
    }
}

void output_all_progesses() {
    unsigned int i;

    for (i = 0; i < downloadNumber; i++) {
        outputProgress(downloadContext[i]->progress);

        if (downloadNumber != 1) {
            printf("\n");
        }
    }

    fflush(stdout);

    if (downloadNumber == 1) {
        /* send \r so that we override this line the next time...*/
        printf("\r");
    }
}

void output_handler (int signum) {
    alarm(1);
    cfg_set_bit(getCfg(), OUTPUT_FLAG);
#if 0
    output_all_progesses();
#endif
}

void* checksum_verification_thread(void *args) {
    struct checksumThreadData *data = args;
    sds md5ChecksumString = data->expectedHash;

    logprintf(LOG_INFO, "Verifying md5-checksum '%s'!", md5ChecksumString);

    HashAlgorithm *md5algo = createHashAlgorithm("MD5");
    uchar hashFromFile[md5algo->hashSize];

    getHashFromFile(md5algo, data->completePath , hashFromFile);
    uchar *expectedHash = convertHashStringToBinary(md5algo, md5ChecksumString);

    if (md5algo->equals(expectedHash, hashFromFile)) {
        logprintf(LOG_INFO, "Checksum-Verification succeeded!");
    }
    else {
        logprintf(LOG_WARN, "Checksum-Verification failed!");
    }

    FREE(expectedHash);
    freeHashAlgo(md5algo);
    sdsfree(data->expectedHash);
    sdsfree(data->completePath);
    FREE(data);

    return NULL;
}

void startChecksumThread(sds md5ChecksumSDS, sds completePath) {
    struct checksumThreadData *threadData = Malloc(sizeof(struct checksumThreadData));
    threadData->completePath = completePath;
    threadData->expectedHash = md5ChecksumSDS;

    pthread_t threadID;

    pthread_create(&threadID, NULL, checksum_verification_thread, threadData);
}

static sds extractMD5 (const char *string) {
    const unsigned int MD5_STR_SIZE = 32;
    char md5ChecksumString[MD5_STR_SIZE+1];
    md5ChecksumString[MD5_STR_SIZE] = (char) 0;

    char *md5sum = strstr(string, "md5sum");

    if (md5sum != NULL) {
        strncpy(md5ChecksumString, md5sum+8, MD5_STR_SIZE);
        return sdsnew(md5ChecksumString);
    }

    md5sum = strstr(string, "MD5");

    if (md5sum != NULL) {
        strncpy(md5ChecksumString, md5sum+4, MD5_STR_SIZE);
        return sdsnew(md5ChecksumString);
    }

    return NULL;
}

static void checkMD5ChecksumNotice(const char * event, irc_parser_result_t *result) {
    if (!str_equals(event, "NOTICE")) {
        return;
    }

    if (result->num_params != 2) {
        return;
    }

    if (lastDownload == NULL) {
        return;
    }

    sds md5ChecksumSDS = extractMD5(result->params[1]);

    if (md5ChecksumSDS == NULL) {
        return;
    }

    startChecksumThread(md5ChecksumSDS, sdsdup(lastDownload->completePath));
}

void dump_event (irc_session_t * session, const char * event, irc_parser_result_t *result)
{
    sds param_string = sdsempty();
    int cnt;

    for (cnt = 0; cnt < result->num_params; cnt++) {
        if (cnt)
            param_string = sdscat(param_string, "|");
        
        char *message_without_color_codes = irc_color_strip_from_mirc(result->params[cnt]);
        param_string = sdscat(param_string, message_without_color_codes);
        free(message_without_color_codes);
    }

    logprintf(LOG_INFO, "Event \"%s\", origin: \"%s\", params: %d [%s]", event, result->nick ? result->nick : "NULL", cnt, param_string);

    checkMD5ChecksumNotice(event, result);
    sdsfree(param_string);
}


void event_join (irc_session_t * session, const char * event, irc_parser_result_t *result)
{
    int i;
    irc_cmd_user_mode (session, "+i");

    if (!cfg.sended) {
        for (i = 0; cfg.dccDownloadArray[i] != NULL; i++) {
            char *botNick = cfg.dccDownloadArray[i]->botNick;
            char *xdccCommand = cfg.dccDownloadArray[i]->xdccCmd;
            
            logprintf(LOG_INFO, "/msg %s %s\n", botNick, xdccCommand);
            bool cmdSendingFailed = irc_cmd_msg(session, botNick, xdccCommand) == 1;

            if (cmdSendingFailed) {
                logprintf(LOG_ERR, "Cannot send xdcc command to bot!");
            }
        }

        cfg.sended = true;
    }	
}


void event_connect (irc_session_t *session, const char * event, irc_parser_result_t *result)
{
    dump_event (session, event, result);

#ifdef ENABLE_SSL
    logprintf(LOG_INFO, "using cipher suite: %s", irc_get_ssl_ciphers_used(session));
#endif

    int i;
    for (i = 0; i < cfg.numChannels; i++) {
        logprintf(LOG_INFO, "joining %s\n", cfg.channelsToJoin[i]);
        irc_cmd_join (session, cfg.channelsToJoin[i], 0);
    }
}


void event_privmsg (irc_session_t * session, const char * event, irc_parser_result_t *result)
{
	
    dump_event (session, event, result);

    printf ("'%s' said me (%s): %s\n", 
            result->nick ? result->nick  : "someone",
            result->params[0], result->params[1] );
}

void event_numeric (irc_session_t * session, unsigned int event, irc_parser_result_t *result)
{
    char buf[24];
    snprintf (buf, sizeof(buf), "%d", event);

    dump_event (session, buf, result);
}

// This callback is used when we receive a file from the remote party

void callback_dcc_recv_file(irc_session_t * session, irc_dcc_t id, int status, void * ctx, const char * data, irc_dcc_size_t length) {
    if (data == NULL) {
        DBG_WARN("callback_dcc_recv_file called with data = NULL!");
        return;
    }

    if (ctx == NULL) {
        DBG_WARN("callback_dcc_recv_file called with ctx = NULL!");
        return;
    }

    if (length == 0) {
        DBG_WARN("callback_dcc_recv_file called with length = 0!");
        return;
    }

    if (status) {
        DBG_ERR("File sent error: %d\nerror desc: %s", status, irc_strerror(status));
        return;
    }

    struct dccDownloadContext *context = (struct dccDownloadContext*) ctx;
    struct dccDownloadProgress *progress = context->progress;

    progress->sizeRcvd += length;
    Write(context->fd, data, length);

    if (unlikely(cfg_get_bit(getCfg(), OUTPUT_FLAG))) {
        output_all_progesses();
        cfg_clear_bit(getCfg(), OUTPUT_FLAG);
    }

    if (unlikely(progress->sizeRcvd == progress->completeFileSize)) {
        alarm(0);
        outputProgress(progress);
        lastDownload = curDownload;
        printf("\nDownload completed!\n");
        fflush(NULL);

        Close(context->fd);
        context->fd = NULL;
        
        finishedDownloads++;
        
        if (!(cfg_get_bit(&cfg, VERIFY_CHECKSUM_FLAG))) {
            if (finishedDownloads == downloadNumber) {
                irc_cmd_quit(cfg.session, "Goodbye!");
            }
        }
    }
}

void callback_dcc_resume_file (irc_session_t * session, irc_dcc_t dccid, int status, void * ctx, const char * data, irc_dcc_size_t length) {
    struct dccDownloadContext *context = (struct dccDownloadContext*) ctx;

    DBG_OK("got to callback_dcc_resume_file\n");
    Seek(context->fd, length, SEEK_SET);
    DBG_OK("before irc_dcc_accept!\n");

    struct dccDownloadProgress *tdp = context->progress;
    tdp->sizeRcvd = length;

    irc_dcc_accept (session, dccid, ctx, callback_dcc_recv_file);
    alarm(1);
    DBG_OK("after irc_dcc_accept!\n");
}

void recvFileRequest (irc_session_t *session, const char *nick, const char *addr, const char *filename, irc_dcc_size_t size, irc_dcc_t dccid)
{
    DBG_OK("DCC send [%d] requested from '%s' (%s): %s (%" IRC_DCC_SIZE_T_FORMAT " bytes)\n", dccid, nick, addr, filename, size);

    sds fileName = sdsnew(filename);	

    /* chars / and \ are not permitted to appear in a valid filename. if someone wants to send us such a file 
       then something is definately wrong. so just exit pgm then and print error msg to user.*/
    char *illegalFilenameChars = "/\\";

    if (sdscontains(fileName, illegalFilenameChars, strlen(illegalFilenameChars))) {
        /* filename contained bad chars. print msg and exit...*/
        logprintf(LOG_ERR, "Someone wants to send us a file that contains / or \\. This is not permitted.\nFilename was: %s", fileName);
        exitPgm(EXIT_FAILURE);
    }
    
    sds completePath = sdsempty();
    sds lastCharOfTargetDir = sdsdup(cfg.targetDir);
    sdsrange(lastCharOfTargetDir, -2, -1);
    
    if (!str_equals(lastCharOfTargetDir, getPathSeperator())) {
        completePath = sdscatprintf(completePath, "%s%s%s", cfg.targetDir, getPathSeperator(), fileName);
    }
    else {
        completePath = sdscatprintf(completePath, "%s%s", cfg.targetDir, fileName);
    }
    
    sdsfree(lastCharOfTargetDir);
    
    struct dccDownloadProgress *progress = newDccProgress(completePath, size);
    curDownload = progress;

    struct dccDownloadContext *context = Malloc(sizeof(struct dccDownloadContext));
    downloadContext[downloadNumber] = context;
    downloadNumber++;
    context->progress = progress;

    DBG_OK("nick at recvFileReq is %s\n", nick);

    if( file_exists (completePath) ) {
        context->fd = Open(completePath, "a");

        off_t fileSize = get_file_size(completePath);

        if (size == (irc_dcc_size_t) fileSize) {
            logprintf(LOG_ERR, "file %s is already downloaded, exit pgm now.", completePath);
            exitPgm(EXIT_FAILURE);
        }

        /* file already exists but is empty. so accept it, rather than resume... */
        if (fileSize == 0) {
            goto accept_flag;
        }

        logprintf(LOG_INFO, "file %s already exists, need to resume.\n", completePath);
        irc_dcc_resume(session, dccid, context, callback_dcc_resume_file, nick, fileSize);

    } 
    else {
        context->fd = Open(completePath, "w");

        logprintf(LOG_INFO, "file %s does not exist. creating file and downloading it now.", completePath);
accept_flag:			
        irc_dcc_accept (session, dccid, context, callback_dcc_recv_file);
        alarm(1);
    }

    sdsfree(fileName);
}

void initCallbacks(irc_callbacks_t *callbacks) {
    memset (callbacks, 0, sizeof(*callbacks));

    callbacks->event_connect = event_connect;
    callbacks->event_join = event_join;
    callbacks->event_dcc_send_req = recvFileRequest;
    callbacks->event_ctcp_rep = dump_event;
    callbacks->event_ctcp_action = dump_event;
    callbacks->event_unknown = dump_event;
    callbacks->event_privmsg = dump_event;
    callbacks->event_notice = dump_event;
    callbacks->event_umode = dump_event;
}

void init_signal(int signum, void (*handler) (int)) {
    struct sigaction act;
    int ret;
    
    memset(&act, 0, sizeof(act));
    sigemptyset (&act.sa_mask);
    
    act.sa_handler = handler;
    act.sa_flags = SA_RESTART;
    
    ret = sigaction(signum, &act, NULL);
    if (ret == -1) {
        logprintf(LOG_ERR, "could not set up signal %d", signum);
        exitPgm(EXIT_FAILURE);
    }
}

int main (int argc, char **argv)
{
    int ret = -1;

    initRand();

    memset(&cfg, 0, sizeof(struct xdccGetConfig));

    cfg.logLevel = LOG_WARN;
    cfg.port = 6667;

    const char *homeDir = getHomeDir();
    sds targetDir = sdscatprintf(sdsempty(), "%s%s%s", homeDir, getPathSeperator(), "Downloads");

#ifdef WINDOWS_BUILD
    free((void*)homeDir);
#endif

    cfg.targetDir = targetDir;
    
    parseConfigFile(&cfg);

    parseArguments(argc, argv, &cfg);

    cfg.ircServer = cfg.args[0];

    cfg.channelsToJoin = parseChannels(cfg.args[1], &cfg.numChannels);
    cfg.dccDownloadArray = parseDccDownloads(cfg.args[2], &cfg.numDownloads);

    downloadContext = Calloc(cfg.numDownloads, sizeof(struct downloadContext*));

    init_signal(SIGINT, interrupt_handler);
    init_signal(SIGALRM, output_handler);
    
    irc_callbacks_t callbacks;
    initCallbacks(&callbacks);
    cfg.session = irc_create_session (&callbacks);

    if (!cfg.session) {
        logprintf(LOG_ERR, "Could not create session\n");
        exitPgm(EXIT_FAILURE);
    }

    logprintf(LOG_INFO, "test message for info");
    logprintf(LOG_QUIET, "test message for quiet");
    logprintf(LOG_WARN, "test message for warn");
    logprintf(LOG_ERR, "test message for error");

    char nick[NICKLEN+1];
    memset(nick, 0, NICKLEN+1);
    createRandomNick(NICKLEN, nick);

    logprintf(LOG_INFO, "nick is %s\n", nick);

#ifdef ENABLE_SSL
    irc_set_cert_verify_callback(cfg.session, openssl_check_certificate_callback);
#endif

    if (cfg_get_bit(&cfg, USE_IPV4_FLAG)) {
        ret = irc_connect4(cfg.session, cfg.ircServer, cfg.port, 0, nick, 0, 0);
    }
#ifdef ENABLE_IPV6
    else if (cfg_get_bit(&cfg, USE_IPV6_FLAG)) {
        ret = irc_connect6(cfg.session, cfg.ircServer, cfg.port, 0, nick, 0, 0);
    }
#endif	
    else {
        ret = irc_connect(cfg.session, cfg.ircServer, cfg.port, 0, nick, 0, 0);
    }

    if (ret != 0) {
        logprintf(LOG_ERR, "Could not connect to server %s and port %u.\nError was: %s\n", cfg.ircServer, cfg.port, irc_strerror(irc_errno(cfg.session)));
        exitPgm(EXIT_FAILURE);
    }

    ret = irc_run (cfg.session);

    if (ret != 0) {
        if (irc_errno(cfg.session) != LIBIRC_ERR_TERMINATED && irc_errno(cfg.session) != LIBIRC_ERR_CLOSED) {
            logprintf(LOG_ERR, "Could not connect or I/O error at server %s and port %u\nError was:%s\n", cfg.ircServer, cfg.port, irc_strerror(irc_errno(cfg.session)));
            exitPgm(EXIT_FAILURE);
        }
    }

    doCleanUp();
    return EXIT_SUCCESS;
}
