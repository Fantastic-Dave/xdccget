/* Copyright (C) 2004-2012 George Yunaev gyunaev@ulduzsoft.com
 *
 * This library is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU Lesser General Public License as published by 
 * the Free Software Foundation; either version 3 of the License, or (at your 
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public 
 * License for more details.
 */

#include <netinet/tcp.h>
#include <inttypes.h>
#include <strings.h>

#include "../helper.h"
#include "dcc.h"
#include "params.h"
#include "irc_line_parser.h"
#include "session.h"

static void send_current_file_offset_to_sender (irc_session_t *session, irc_dcc_session_t *dcc);
static void recv_dcc_file(irc_session_t *ircsession, irc_dcc_session_t *dcc);

static irc_dcc_session_t * libirc_find_dcc_session(irc_session_t * session, irc_dcc_t dccid, int lock_list) {
    irc_dcc_session_t * s, *found = 0;

    if (lock_list)
        libirc_mutex_lock(&session->mutex_dcc);

    for (s = session->dcc_sessions; s; s = s->next) {
        if (s->id == dccid) {
            found = s;
            break;
        }
    }

    if (found == 0 && lock_list)
        libirc_mutex_unlock(&session->mutex_dcc);

    return found;
}

static void libirc_dcc_destroy_nolock(irc_session_t * session, irc_dcc_t dccid)
{
    irc_dcc_session_t * dcc = libirc_find_dcc_session(session, dccid, 0);

    if (dcc == NULL) {
        return;
    }

#ifdef ENABLE_SSL
    if (dcc->ssl) {
        SSL_free(dcc->ssl_ctx);
    }
#endif

    if (dcc->sock >= 0) {
        socket_close(&dcc->sock);
    }

    dcc->state = LIBIRC_STATE_REMOVED;
}

static inline int ssl_read_wrapper(irc_session_t *session, irc_dcc_session_t *dcc, void *buf, int num, int *sslError) {
#ifdef ENABLE_SSL
    int length;
    
    *sslError = SSL_ERROR_NONE;

    length = SSL_read(dcc->ssl_ctx, buf, num);

    if (length == -1) {
        int ssl_err = SSL_get_error(dcc->ssl_ctx, length);
        *sslError = ssl_err;

        if (ssl_err == SSL_ERROR_WANT_READ) {
            //DBG_WARN("SSL_ERROR_WANT_READ on ssl_read_wrapper!");
        }
        else if (ssl_err == SSL_ERROR_WANT_WRITE) {
            DBG_WARN("SSL_ERROR_WANT_WRITE on ssl_read_wrapper!");
        }
        else {
            DBG_ERR("fatal ssl-error on ssl_read_wrapper was %s", ERR_error_string(ssl_err, NULL));
        }
    }

    return length;
#else
    return -1;
#endif
}

static inline int ssl_write_wrapper(irc_session_t *session, irc_dcc_session_t *dcc, void *buf, int num, int *sslError) {
#ifdef ENABLE_SSL
    int length;
    
    *sslError = SSL_ERROR_NONE;

    length = SSL_write(dcc->ssl_ctx, buf, num);

    if (length == -1) {
        int ssl_err = SSL_get_error(dcc->ssl_ctx, length);
        *sslError = ssl_err;

        if (ssl_err == SSL_ERROR_WANT_READ) {
            DBG_WARN("SSL_ERROR_WANT_READ on ssl_write_wrapper!");
        }
        else if (ssl_err == SSL_ERROR_WANT_WRITE) {
            DBG_WARN("SSL_ERROR_WANT_WRITE on ssl_write_wrapper!");
        }
        else {
            DBG_ERR("fatal ssl-error on ssl_write_wrapper was %s", ERR_error_string(ssl_err, NULL));
        }
    }

    return length;
#else
    return -1;
#endif
}

static inline int hasSocketPendingData (irc_dcc_session_t *dcc) {
#if defined (ENABLE_SSL)
    if (dcc->ssl) {
        return SSL_pending(dcc->ssl_ctx) != 0;
    }
#endif
    return 0;
}

static void recv_dcc_file(irc_session_t *ircsession, irc_dcc_session_t *dcc) {
    int rcvdBytes, err = 0;

    size_t amount = LIBIRC_DCC_BUFFER_SIZE;

    do {
#ifdef ENABLE_SSL
        if (dcc->ssl == 0)
            rcvdBytes = socket_recv(&dcc->sock, dcc->incoming_buf, amount);
        else {
            int sslError = 0;
            rcvdBytes = ssl_read_wrapper(ircsession, dcc, dcc->incoming_buf, amount, &sslError);

            if (sslError == SSL_ERROR_WANT_READ) {
                return;
            }
            else if (sslError == SSL_ERROR_WANT_WRITE) {
                dcc->state = LIBIRC_STATE_CONFIRM_SIZE;
                return;
            }
        }
#else
        rcvdBytes = socket_recv(&dcc->sock, dcc->incoming_buf, amount);
#endif

        if (rcvdBytes < 0) {
            err = LIBIRC_ERR_READ;
        }
        else if (rcvdBytes == 0) {
            err = LIBIRC_ERR_CLOSED;
        }
        else {
            libirc_mutex_unlock(&ircsession->mutex_dcc);

            dcc->file_confirm_offset += rcvdBytes;
            (*dcc->cb)(ircsession, dcc->id, err, dcc->ctx, dcc->incoming_buf, rcvdBytes);
            dcc->state = LIBIRC_STATE_CONFIRM_SIZE;

            libirc_mutex_lock(&ircsession->mutex_dcc);
        }

        /*
         * If error arises somewhere above, we inform the caller 
         * of failure, and destroy this session.
         */
        if (err) {
            libirc_mutex_unlock(&ircsession->mutex_dcc);
            (*dcc->cb)(ircsession, dcc->id, err, dcc->ctx, 0, 0);
            libirc_mutex_lock(&ircsession->mutex_dcc);
            libirc_dcc_destroy_nolock(ircsession, dcc->id);
            return;
        }
    }
    while (hasSocketPendingData(dcc));
}

static void send_current_file_offset_to_sender (irc_session_t *session, irc_dcc_session_t *dcc) {
    int sentBytes, err = 0;

    // we convert out irc_dcc_size_t to uint32_t, because it's defined like that in dcc...
    uint32_t confirmSizeNetworkOrder = htobe32(dcc->file_confirm_offset);
    size_t offset = sizeof(confirmSizeNetworkOrder);

#ifdef ENABLE_SSL
    if (dcc->ssl == 0)
        sentBytes = socket_send(&dcc->sock, &confirmSizeNetworkOrder, offset);
    else {
        int sslError = 0;
        sentBytes = ssl_write_wrapper(session, dcc, &confirmSizeNetworkOrder, offset, &sslError);

        if (sslError == SSL_ERROR_WANT_READ) {
            dcc->state = LIBIRC_STATE_CONNECTED;
            return;
        }
        else if (sslError == SSL_ERROR_WANT_WRITE) {
            return;
        }
    }
#else
    sentBytes = socket_send(&dcc->sock, &confirmSizeNetworkOrder, offset);
#endif
    if (sentBytes < 0) {
        DBG_WARN("err send length < 0");
        DBG_WARN("error msg: %s\n", strerror(errno));
        err = LIBIRC_ERR_WRITE;
    } else if (sentBytes == 0) {
        err = LIBIRC_ERR_CLOSED;
    } else {
        if (dcc->received_file_size == dcc->file_confirm_offset) {
            DBG_OK("dcc->received_file_size == dcc->file_confirm_offset");
            libirc_mutex_unlock(&session->mutex_dcc);
            (*dcc->cb)(session, dcc->id, 0, dcc->ctx, 0, 0);
			libirc_mutex_lock(&session->mutex_dcc);
            libirc_dcc_destroy_nolock(session, dcc->id);
        } else {
            /* Continue to receive the file */
            dcc->state = LIBIRC_STATE_CONNECTED;
        }
    }

    /*
     * If error arises somewhere above, we inform the caller 
     * of failure, and destroy this session.
     */
    if (err) {
        libirc_mutex_unlock(&session->mutex_dcc);
        (*dcc->cb)(session, dcc->id, err, dcc->ctx, 0, 0);
        libirc_mutex_lock(&session->mutex_dcc);

        //libirc_dcc_destroy_nolock (ircsession, dcc->id);
    }
}

static irc_dcc_session_t * libirc_find_dcc_session_by_port(irc_session_t * session, unsigned short port, int lock_list) {
    irc_dcc_session_t * s, *found = 0;

    if (lock_list)
        libirc_mutex_lock(&session->mutex_dcc);

    for (s = session->dcc_sessions; s; s = s->next) {
        if (ntohs(s->remote_addr.sin_port) == port) {
            found = s;
            break;
        }
    }

    if (found == 0 && lock_list)
        libirc_mutex_unlock(&session->mutex_dcc);

    return found;
}

static void libirc_remove_dcc_session(irc_session_t * session, irc_dcc_session_t * dcc, int lock_list) {
    if (dcc->sock >= 0)
        socket_close(&dcc->sock);

    libirc_mutex_destroy(&dcc->mutex_outbuf);

    if (lock_list)
        libirc_mutex_lock(&session->mutex_dcc);

    if (session->dcc_sessions != dcc) {
        irc_dcc_session_t * s;
        for (s = session->dcc_sessions; s; s = s->next) {
            if (s->next == dcc) {
                s->next = dcc->next;
                break;
            }
        }
    } else
        session->dcc_sessions = dcc->next;

    if (lock_list)
        libirc_mutex_unlock(&session->mutex_dcc);

    free(dcc);
}

static void libirc_dcc_add_descriptors(irc_session_t * ircsession, fd_set *in_set, fd_set *out_set, int * maxfd) {
    irc_dcc_session_t * dcc, *dcc_next;

    libirc_mutex_lock(&ircsession->mutex_dcc);

    // Preprocessing DCC list:
    // - ask DCC send callbacks for data;
    // - remove unused DCC structures
    for (dcc = ircsession->dcc_sessions; dcc; dcc = dcc_next) {
        dcc_next = dcc->next;

        // Clean up unused sessions
        if (dcc->state == LIBIRC_STATE_REMOVED)
            libirc_remove_dcc_session(ircsession, dcc, 0);
    }

    for (dcc = ircsession->dcc_sessions; dcc; dcc = dcc->next) {
        switch (dcc->state) {
            case LIBIRC_STATE_CONNECTING:
                // While connection, only out_set descriptor should be set
                libirc_add_to_set(dcc->sock, out_set, maxfd);
                break;

            case LIBIRC_STATE_CONNECTED:
                libirc_add_to_set(dcc->sock, in_set, maxfd);
                break;

            case LIBIRC_STATE_CONFIRM_SIZE:
                libirc_add_to_set(dcc->sock, out_set, maxfd);
                break;
            case LIBIRC_STATE_WAITING_FOR_RESUME_ACK:

            break;
            default:
                DBG_WARN("unknown state at libirc_dcc_add_descriptors");
                break;
        }
    }

    libirc_mutex_unlock(&ircsession->mutex_dcc);
}

static void handleConnectingState(irc_session_t * ircsession, irc_dcc_session_t *dcc, fd_set *in_set, fd_set *out_set) {
    if (FD_ISSET(dcc->sock, out_set)) {
        // Now we have to determine whether the socket is connected 
        // or the connect is failed
        struct sockaddr_in saddr;
        socklen_t slen = sizeof (saddr);
        int err = 0;

        if (getpeername(dcc->sock, (struct sockaddr*) &saddr, &slen) < 0)
            err = LIBIRC_ERR_CONNECT;

        // On success, change the state
        if (err == 0)
            dcc->state = LIBIRC_STATE_CONNECTED;

        if (err)
            libirc_dcc_destroy_nolock(ircsession, dcc->id);

    }
}

static void handleConnectedState(irc_session_t * ircsession, irc_dcc_session_t *dcc, fd_set *in_set, fd_set *out_set) {
    if (FD_ISSET(dcc->sock, in_set)) {
       recv_dcc_file(ircsession, dcc);
    }
    else {
        //printf("no incoming data at handleConnectedState!\n");
        //printf("dcc->received_file_size = %u, dcc->file_confirm_offset = %u\n", dcc->received_file_size, dcc->file_confirm_offset);
    }
}

static void handleConfirmSizeState(irc_session_t * ircsession, irc_dcc_session_t *dcc, fd_set *in_set, fd_set *out_set) {
    if (FD_ISSET(dcc->sock, out_set)) {	
        send_current_file_offset_to_sender(ircsession, dcc);
    }
}

static void libirc_dcc_process_descriptors(irc_session_t * ircsession, fd_set *in_set, fd_set *out_set) {
    irc_dcc_session_t * dcc;

    /*
     * We need to use such a complex scheme here, because on every callback
     * a number of DCC sessions could be destroyed.
     */
    libirc_mutex_lock(&ircsession->mutex_dcc);

    for (dcc = ircsession->dcc_sessions; dcc; dcc = dcc->next) {
        switch (dcc->state) {
            case LIBIRC_STATE_CONNECTING:
                //printf("LIBIRC_STATE_CONNECTING\n");
                handleConnectingState(ircsession, dcc, in_set, out_set);
            break;
            case LIBIRC_STATE_CONNECTED:
                //printf("LIBIRC_STATE_CONNECTED\n");
                handleConnectedState(ircsession, dcc, in_set, out_set);
            break;
            case LIBIRC_STATE_CONFIRM_SIZE:
                //printf("LIBIRC_STATE_CONFIRM_SIZE\n");
                handleConfirmSizeState(ircsession, dcc, in_set, out_set);
            break;
            case LIBIRC_STATE_WAITING_FOR_RESUME_ACK:

            break;
            default:
                DBG_WARN("unknown state %d at libirc_dcc_process_descriptors!", dcc->state);
            break;
        }
    }

    libirc_mutex_unlock(&ircsession->mutex_dcc);
}

#if 0
static void optimizeSocketBufferSize(const irc_dcc_session_t *dcc) {
    int bufferSize = 0;
    socklen_t bufSizeLen = sizeof(int);

    getsockopt(dcc->sock, SOL_SOCKET, SO_RCVBUF, &bufferSize, &bufSizeLen);
    bufferSize *= 2;
    bufferSize *= 16;

    DBG_OK("got buffer size of %d!", bufferSize);

    setsockopt(dcc->sock, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
}

#endif

static int libirc_new_dcc_session(irc_session_t * session, unsigned long ip, unsigned short port, void * ctx, irc_dcc_session_t ** pdcc, int ssl) {
    irc_dcc_session_t * dcc = malloc(sizeof (irc_dcc_session_t));

    if (!dcc)
        return LIBIRC_ERR_NOMEM;

    // setup
    memset(dcc, 0, sizeof (irc_dcc_session_t));

    dcc->dccsend_file_fp = 0;

    if (libirc_mutex_init(&dcc->mutex_outbuf))
        goto cleanup_exit_error;

    if (socket_create(PF_INET, SOCK_STREAM, &dcc->sock))
        goto cleanup_exit_error;

	// make socket non-blocking, so connect() call won't block
    if (socket_make_nonblocking(&dcc->sock))
        goto cleanup_exit_error;

    //optimizeSocketBufferSize(dcc);
    
#if defined (ENABLE_SSL)
    dcc->ssl = 0;
    if (ssl) {
        dcc->ssl = 1;
        if (!isSslIntitialized()) {
            DBG_OK("need to init ssl context!");
            int ret = initSslContext(session);
            if (ret != 0) {
                DBG_ERR("ssl context cant be inited!");
                exit(-1);
            }

        }
        dcc->ssl_ctx = SSL_new(ssl_context);
        SSL_set_fd(dcc->ssl_ctx, dcc->sock);
        if (session->verify_callback != NULL)
            SSL_set_verify(dcc->ssl_ctx, SSL_VERIFY_PEER, session->verify_callback);
        else
            SSL_set_verify(dcc->ssl_ctx, SSL_VERIFY_NONE, NULL);
        // Since we're connecting on our own, tell openssl about it
        SSL_set_connect_state(dcc->ssl_ctx);
    }
#endif

    memset(&dcc->remote_addr, 0, sizeof (dcc->remote_addr));
    dcc->remote_addr.sin_family = AF_INET;
    dcc->remote_addr.sin_addr.s_addr = htonl(ip); // what idiot came up with idea to send IP address in host-byteorder?
    dcc->remote_addr.sin_port = htons(port);

    dcc->state = LIBIRC_STATE_INIT;

    dcc->ctx = ctx;
    time(&dcc->timeout);

    // and store it
    libirc_mutex_lock(&session->mutex_dcc);

    dcc->id = session->dcc_last_id++;
    dcc->next = session->dcc_sessions;
    session->dcc_sessions = dcc;

    libirc_mutex_unlock(&session->mutex_dcc);

    *pdcc = dcc;
    return 0;

cleanup_exit_error:
    if (dcc->sock >= 0)
        socket_close(&dcc->sock);

    free(dcc);
    return LIBIRC_ERR_SOCKET;
}

int irc_dcc_destroy(irc_session_t * session, irc_dcc_t dccid) {
    // This function doesn't actually destroy the session; it just changes
    // its state to "removed" and closes the socket. The memory is actually
    // freed after the processing loop.
    irc_dcc_session_t * dcc = libirc_find_dcc_session(session, dccid, 1);

    if (!dcc)
        return 1;

    if (dcc->sock >= 0)
        socket_close(&dcc->sock);

    dcc->state = LIBIRC_STATE_REMOVED;

    libirc_mutex_unlock(&session->mutex_dcc);
    return 0;
}

static void accept_dcc_send(irc_session_t * session, const char * nick, const char * req, char *filename, unsigned long ip, irc_dcc_size_t size, unsigned short port, int ssl) {
    DBG_OK("---- got dcc send req: %s ---", req);
    if (session->callbacks.event_dcc_send_req) {
        irc_dcc_session_t * dcc;

        int err = libirc_new_dcc_session(session, ip, port, 0, &dcc, ssl);
        if (err) {
            session->lasterror = err;
            return;
        }

        (*session->callbacks.event_dcc_send_req) (session,
                nick,
                inet_ntoa(dcc->remote_addr.sin_addr),
                filename,
                size,
                dcc->id);

        dcc->received_file_size = size;
    }
}

static inline bool isValidRequestFromNick(struct dccDownload **dccDownloads, char *botNick) {
    unsigned int i = 0;

    if (dccDownloads == NULL) {
        return false;
    }

    for (i = 0; dccDownloads[i]; i++) {
        if (strcasecmp(dccDownloads[i]->botNick, botNick) == 0) {
            return true;
        }
    }

    return false;
}

static void libirc_dcc_request(irc_session_t * session, irc_parser_result_t *result, const char * req) {
    char filenamebuf[LIBIRC_BUFFER_SIZE+1];
    unsigned long ip;
    irc_dcc_size_t size;
    unsigned short port;
    
    filenamebuf[LIBIRC_BUFFER_SIZE] = (char) 0;
    DBG_OK("---- got dcc req: %s ---", req);

    if (!isValidRequestFromNick(getCfg()->dccDownloadArray, result->nick)) {
        DBG_WARN("received unknown dcc req from nick %s. ignoring that request!", result->nick);
        return;
    }
    
    if (sscanf(req, "DCC SEND %"LIBIRC_BUFFER_SIZE_STR"s %lu %hu %" IRC_DCC_SIZE_T_FORMAT, filenamebuf, &ip, &port, &size) == 4) {
        accept_dcc_send(session, result->nick, req, filenamebuf, ip, size, port, 0);
        return;
    } else if (sscanf(req, "DCC SEND %"LIBIRC_BUFFER_SIZE_STR"s %lu %hu", filenamebuf, &ip, &port) == 3) {
        size = 0;
        accept_dcc_send(session, result->nick, req, filenamebuf, ip, size, port, 0);
        return;
    }
#if defined (ENABLE_SSL)
    else if (sscanf(req, "DCC SSEND %"LIBIRC_BUFFER_SIZE_STR"s %lu %hu %" IRC_DCC_SIZE_T_FORMAT, filenamebuf, &ip, &port, &size) == 4) {
        accept_dcc_send(session, result->nick, req, filenamebuf, ip, size, port, 1);
        return;
    }
#endif
    else if (sscanf(req, "DCC ACCEPT file.ext %hu %" IRC_DCC_SIZE_T_FORMAT, &port, &size) == 2) {
        DBG_OK("---- got dcc accept req: %hu %" IRC_DCC_SIZE_T_FORMAT " ---", port, size);
        irc_dcc_session_t * dcc;
        dcc = libirc_find_dcc_session_by_port(session, port, 1);
        if (dcc == NULL) {
            DBG_WARN("cant find open dcc session with port = %hu!", port);
            return;
        }

        if (dcc->state != LIBIRC_STATE_WAITING_FOR_RESUME_ACK) {
            DBG_WARN("dcc->state != LIBIRC_STATE_WAITING_FOR_RESUME_ACK");
            return;
        }

        dcc->state = LIBIRC_STATE_INIT;

        dcc->file_confirm_offset = size;

        libirc_mutex_unlock(&session->mutex_dcc);

        (*dcc->cb) (session, dcc->id, 1, dcc->ctx, NULL, size);

        return;

    }
#if defined (ENABLE_DEBUG)
    fprintf(stderr, "BUG: Unhandled DCC message: %s\n", req);
    abort();
#endif
}

int irc_dcc_accept(irc_session_t * session, irc_dcc_t dccid, void * ctx, irc_dcc_callback_t callback) {
    irc_dcc_session_t * dcc = libirc_find_dcc_session(session, dccid, 1);

    if (!dcc)
        return 1;

    if (dcc->state != LIBIRC_STATE_INIT) {
        session->lasterror = LIBIRC_ERR_STATE;
        libirc_mutex_unlock(&session->mutex_dcc);
        return 1;
    }

    dcc->cb = callback;
    dcc->ctx = ctx;

    DBG_OK("going to socket_connect!");

    // Initiate the connect

    if (socket_connect(&dcc->sock, (struct sockaddr *) &dcc->remote_addr, sizeof (dcc->remote_addr))) {
        libirc_dcc_destroy_nolock(session, dccid);
        libirc_mutex_unlock(&session->mutex_dcc);
        session->lasterror = LIBIRC_ERR_CONNECT;
        return 1;
    }
    
#ifdef ENABLE_SSL
    if (dcc->ssl == 1) {
        DBG_OK("using ssl!");

        while (1) {
            int err = SSL_connect(dcc->ssl_ctx);
            if (err <= 0) {
                int ssl_err = SSL_get_error(dcc->ssl_ctx, err);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                    continue;
                } else {
                    DBG_WARN("error was %s", ERR_error_string(ssl_err, NULL));
                    session->lasterror = LIBIRC_ERR_CONNECT;
                    return 1;
                }
            }
            DBG_OK("ssl_connect succeded!");
            break;
        }
        
        const char *ciphers_used = "None";
        ciphers_used = SSL_get_cipher_name(dcc->ssl_ctx);
        logprintf(LOG_INFO, "using cipher suite: %s for dcc connection", ciphers_used);
    }
#endif

    DBG_OK("connect succeded2!");

    dcc->state = LIBIRC_STATE_CONNECTING;
#ifdef ENABLE_SSL
    if (dcc->ssl) {
        dcc->state = LIBIRC_STATE_CONNECTED;
    }
#endif
    libirc_mutex_unlock(&session->mutex_dcc);
    return 0;
}

int irc_dcc_resume(irc_session_t * session, irc_dcc_t dccid, void * ctx, irc_dcc_callback_t callback, const char *nick, irc_dcc_size_t filePosition) {
    irc_dcc_session_t * dcc = libirc_find_dcc_session(session, dccid, 1);

    if (!dcc)
        return 1;

    if (dcc->state != LIBIRC_STATE_INIT) {
        session->lasterror = LIBIRC_ERR_STATE;
        libirc_mutex_unlock(&session->mutex_dcc);
        return 1;
    }
    dcc->cb = callback;
    dcc->ctx = ctx;

    // ctcp msg to bot
    char buf[512];
    snprintf(buf, sizeof(buf), "DCC RESUME file.ext %hu %" IRC_DCC_SIZE_T_FORMAT "", ntohs(dcc->remote_addr.sin_port), filePosition);
    DBG_OK("%s", buf);
    irc_cmd_ctcp_request(session, nick, buf);
    dcc->state = LIBIRC_STATE_WAITING_FOR_RESUME_ACK;
    libirc_mutex_unlock(&session->mutex_dcc);
    return 0;

}

int irc_dcc_decline(irc_session_t * session, irc_dcc_t dccid) {
    irc_dcc_session_t * dcc = libirc_find_dcc_session(session, dccid, 1);

    if (!dcc)
        return 1;

    if (dcc->state != LIBIRC_STATE_INIT) {
        session->lasterror = LIBIRC_ERR_STATE;
        libirc_mutex_unlock(&session->mutex_dcc);
        return 1;
    }

    libirc_dcc_destroy_nolock(session, dccid);
    libirc_mutex_unlock(&session->mutex_dcc);
    return 0;
}
