/* 
 * Copyright (C) 2004-2012 George Yunaev gyunaev@ulduzsoft.com
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


#if defined (ENABLE_SSL)

#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifndef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
# define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0
#endif

#include "session.h"

// Nonzero if OpenSSL has been initialized
static SSL_CTX * ssl_context = NULL;

// This array will store all of the mutexes available to OpenSSL
static pthread_mutex_t * mutex_buf = 0;

// OpenSSL callback to utilize static locks

static void cb_openssl_locking_function(int mode, int n, const char * file, int line) {
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&mutex_buf[n]);
    else
        pthread_mutex_unlock(&mutex_buf[n]);
}

// OpenSSL callback to get the thread ID

static unsigned long cb_openssl_id_function() {
    return ((unsigned long) pthread_self());
}

static int alloc_mutexes(unsigned int total) {
    int i;

    // Enable thread safety in OpenSSL
    mutex_buf = (pthread_mutex_t*) malloc(total * sizeof (pthread_mutex_t));

    if (!mutex_buf)
        return -1;

    for (i = 0; i < total; i++)
        pthread_mutex_init(&(mutex_buf[i]), 0);

    return 0;
}

#endif

#ifdef ENABLE_SSL
int isSslIntitialized() {
    return ssl_context != NULL;
}

int initSslContext(irc_session_t *session) {
    // better settings, but some bots dont support those all...
    //const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
    //const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;

    const char * PREFERRED_CIPHERS = "ALL:!RC4:!PSK:!SRP:!ADH:!LOW:!EXP:!MD5:!aNULL@STRENGTH";
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

    // Load the strings and init the library
    SSL_load_error_strings();

    // Enable thread safety in OpenSSL
    if (alloc_mutexes(CRYPTO_num_locks()))
        return LIBIRC_ERR_NOMEM;

    // Register our callbacks
    CRYPTO_set_id_callback(cb_openssl_id_function);
    CRYPTO_set_locking_callback(cb_openssl_locking_function);

    if (!SSL_library_init())
        return LIBIRC_ERR_SSL_INIT_FAILED;

    if (RAND_status () != 1)
        return LIBIRC_ERR_SSL_INIT_FAILED;

    // Create an SSL context; currently a single context is used for all connections
    // hint: SSLv23_method means: TLS 1.0, 1.1 and 1.2. we disabled sslv2 and sslv3 with the flags above...
    ssl_context = SSL_CTX_new(SSLv23_method());

    if (!ssl_context)
        return LIBIRC_ERR_SSL_INIT_FAILED;

    if ((SSL_CTX_set_options(ssl_context, flags) & flags) == 0)
        return LIBIRC_ERR_SSL_INIT_FAILED;

    if (SSL_CTX_set_cipher_list(ssl_context, PREFERRED_CIPHERS) != 1)
        return LIBIRC_ERR_SSL_INIT_FAILED;

    // Disable session caching
    SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_OFF);

    if (session->verify_callback == NULL) {
        SSL_CTX_set_verify(ssl_context, SSL_VERIFY_NONE, 0);
    } else {
        SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, session->verify_callback);
    }
    
    SSL_CTX_set_default_verify_paths(ssl_context);

    // Enable SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER so we can move the buffer during sending
    SSL_CTX_set_mode(ssl_context, SSL_CTX_get_mode(ssl_context) | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

    return 0;
}

// Initializes the SSL context. Must be called after the socket is created.

static int ssl_init(irc_session_t * session) {
    if (!isSslIntitialized()) {
        int ret = initSslContext(session);
        if (ret != 0) {
            return ret;
        }
    }

    // Get the SSL context
    session->ssl = SSL_new(ssl_context);

    if (!session->ssl)
        return LIBIRC_ERR_SSL_INIT_FAILED;

    // Let OpenSSL use our socket
    if (SSL_set_fd(session->ssl, session->sock) != 1)
        return LIBIRC_ERR_SSL_INIT_FAILED;

    // Since we're connecting on our own, tell openssl about it
    SSL_set_connect_state(session->ssl);

#ifdef HOSTNAME_VALIDATION
    // enable automatic check for hostname validation
    X509_VERIFY_PARAM *param = SSL_get0_param(session->ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    X509_VERIFY_PARAM_set1_host(param, session->server, 0);
#endif

    return 0;
}

static void ssl_handle_error(irc_session_t * session, int ssl_error) {
    if (ERR_GET_LIB(ssl_error) == ERR_LIB_SSL) {
        if (ERR_GET_REASON(ssl_error) == SSL_R_CERTIFICATE_VERIFY_FAILED) {
            session->lasterror = LIBIRC_ERR_SSL_CERT_VERIFY_FAILED;
            return;
        }

        if (ERR_GET_REASON(ssl_error) == SSL_R_UNKNOWN_PROTOCOL) {
            session->lasterror = LIBIRC_ERR_CONNECT_SSL_FAILED;
            return;
        }
    }

#if defined (ENABLE_DEBUG)
    if (IS_DEBUG_ENABLED(session))
        fprintf(stderr, "[DEBUG] SSL error: %s\n\t(%d, %d)\n",
            ERR_error_string(ssl_error, NULL), ERR_GET_LIB(ssl_error), ERR_GET_REASON(ssl_error));
#endif
}

static int ssl_recv(irc_session_t * session) {
    unsigned int amount = (sizeof (session->incoming_buf) - 1) - session->incoming_offset;

    ERR_clear_error();

    // Read up to m_bufferLength bytes
    int count = SSL_read(session->ssl, session->incoming_buf + session->incoming_offset, amount);

    if (count > 0)
        return count;
    else if (count == 0)
        return -1; // remote connection closed
    else {
        int ssl_error = SSL_get_error(session->ssl, count);

        // Handle SSL error since not all of them are actually errors
        switch (ssl_error) {
            case SSL_ERROR_WANT_READ:
                // This is not really an error. We received something, but
                // OpenSSL gave nothing to us because all it read was
                // internal data. Repeat the same read.
                return 0;

            case SSL_ERROR_WANT_WRITE:
                // This is not really an error. We received something, but
                // now OpenSSL needs to send the data before returning any
                // data to us (like negotiations). This means we'd need
                // to wait for WRITE event, but call SSL_read() again.
                session->flags |= SESSIONFL_SSL_READ_WANTS_WRITE;
                return 0;
        }

        // This is an SSL error, handle it
        ssl_handle_error(session, ERR_get_error());
    }

    return -1;
}

static int ssl_send(irc_session_t * session) {
    ERR_clear_error();

    int count = SSL_write(session->ssl, session->outgoing_buf, session->outgoing_offset);

    if (count > 0)
        return count;
    else if (count == 0)
        return -1;
    else {
        int ssl_error = SSL_get_error(session->ssl, count);

        switch (ssl_error) {
            case SSL_ERROR_WANT_READ:
                // This is not really an error. We sent some internal OpenSSL data,
                // but now it needs to read more data before it can send anything.
                // Thus we wait for READ event, but will call SSL_write() again.
                session->flags |= SESSIONFL_SSL_WRITE_WANTS_READ;
                return 0;

            case SSL_ERROR_WANT_WRITE:
                // This is not really an error. We sent some data, but now OpenSSL
                // wants to send some internal data before sending ours.
                // Repeat the same write.
                return 0;
        }

        // This is an SSL error, handle it
        ssl_handle_error(session, ERR_get_error());
    }

    return -1;
}

#endif


// Handles both SSL and non-SSL reads.
// Returns -1 in case there is an error and socket should be closed/connection terminated
// Returns 0 in case there is a temporary error and the call should be retried (SSL_WANTS_WRITE case)
// Returns a positive number if we actually read something

static int session_socket_read(irc_session_t * session) {
    int length;

#if defined (ENABLE_SSL)
    if (session->ssl) {
        // Yes, I know this is tricky
        if (session->flags & SESSIONFL_SSL_READ_WANTS_WRITE) {
            session->flags &= ~SESSIONFL_SSL_READ_WANTS_WRITE;
            ssl_send(session);
            return 0;
        }

        return ssl_recv(session);
    }
#endif

    length = socket_recv(&session->sock,
            session->incoming_buf + session->incoming_offset,
            (sizeof (session->incoming_buf) - 1) - session->incoming_offset);

    // There is no "retry" errors for regular sockets
    if (length <= 0)
        return -1;

    return length;
}

// Handles both SSL and non-SSL writes.
// Returns -1 in case there is an error and socket should be closed/connection terminated
// Returns 0 in case there is a temporary error and the call should be retried (SSL_WANTS_WRITE case)
// Returns a positive number if we actually sent something

static int session_socket_write(irc_session_t * session) {
    int length;

#if defined (ENABLE_SSL)
    if (session->ssl) {
        // Yep
        if (session->flags & SESSIONFL_SSL_WRITE_WANTS_READ) {
            session->flags &= ~SESSIONFL_SSL_WRITE_WANTS_READ;
            ssl_recv(session);
            return 0;
        }

        return ssl_send(session);
    }
#endif

    length = socket_send(&session->sock, session->outgoing_buf, session->outgoing_offset);

    // There is no "retry" errors for regular sockets
    if (length <= 0)
        return -1;

    return length;
}
