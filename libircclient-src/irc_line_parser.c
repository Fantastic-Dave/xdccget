#include "session.h"
#include "irc_line_parser.h"

#include "../helper.h"
#include "irc_parser.h"

/*
     * From RFC 1459:
     *  <message>  ::= [':' <prefix> <SPACE> ] <command> <params> <crlf>
     *  <prefix>   ::= <servername> | <nick> [ '!' <user> ] [ '@' <host> ]
     *  <command>  ::= <letter> { <letter> } | <number> <number> <number>
     *  <SPACE>    ::= ' ' { ' ' }
     *  <params>   ::= <SPACE> [ ':' <trailing> | <middle> <params> ]
     *  <middle>   ::= <Any *non-empty* sequence of octets not including SPACE
     *                 or NUL or CR or LF, the first of which may not be ':'>
     *  <trailing> ::= <Any, possibly *empty*, sequence of octets not including
     *                   NUL or CR or LF>
*/

void free_line_parser(irc_parser *parser) {
    FREE(parser->data);
    FREE(parser);
}

void free_parser_result (irc_parser *parser) {
    irc_parser_result_t *result = parser->data;
    unsigned int i = 0;
    
    if (result == NULL) {
        return;
    }
    
    FREE(result->nick);
    FREE(result->name);
    FREE(result->host);
    FREE(result->command);
    
    for (i = 0; i < result->num_params; i++) {
        FREE(result->params[i]);
    }

    result->num_params = 0;
}

static inline char* calloc_and_copy_string(const char *string, size_t len) {
    char *result = Calloc(len+1, sizeof(char));
    strncpy(result, string, len);
    return result;
}

static int on_nick(irc_parser *parser, const char *at, size_t len) {
    irc_parser_result_t *result = parser->data;
    result->nick = calloc_and_copy_string(at, len);
    return 0;
}

static int on_name(irc_parser *parser, const char *at, size_t len) {
    irc_parser_result_t *result = parser->data;
    result->name = calloc_and_copy_string(at, len);
    return 0;
}

static int on_host(irc_parser *parser, const char *at, size_t len) {
    irc_parser_result_t *result = parser->data;
    result->host = calloc_and_copy_string(at, len);
    return 0;
}

static int on_command(irc_parser *parser, const char *at, size_t len) {
    irc_parser_result_t *result = parser->data;
    result->command = calloc_and_copy_string(at, len);
    return 0;
}

static int on_param(irc_parser *parser, const char *at, size_t len) {
    irc_parser_result_t *result = parser->data;
    
    if (result->num_params < MAX_PARAMS_ALLOWED) {
        result->params[result->num_params] = calloc_and_copy_string(at, len);
        result->num_params++;
    }
    else {
        DBG_WARN("reached max params at irc_line_parsing!");
    }
    
    return 0;
}

static int on_error(irc_parser *parser, const char *at, size_t len) {
    DBG_ERR("Error '%s' at parsing the irc line!", irc_parser_error_string(parser));
    return 0;
}

static inline void print_parser_result(irc_parser_result_t *result) {    
    unsigned int i = 0;
    if (result->nick != NULL)
        logprintf(LOG_INFO, ", nick = %s", result->nick);
    
    if (result->name != NULL)
        logprintf(LOG_INFO, ", name = %s", result->name);
    
    if (result->host != NULL)
        logprintf(LOG_INFO, ", host = %s", result->host);
    
    logprintf(LOG_INFO, " command='%s'", result->command);
    
    for (i = 0; i < result->num_params; i++) {
        logprintf(LOG_INFO, " param[%u]=%s, ", i, result->params[i]);
    }
}

static inline sds create_prefix_from_result(irc_parser_result_t *result) {
    /* *  <prefix>   ::= <servername> | <nick> [ '!' <user> ] [ '@' <host> ]*/
    sds prefix = sdsempty();
    
    if (result->nick != NULL) {
        prefix = sdscatprintf(prefix, "%s", result->nick);
        
        if (result->name != NULL) {
            prefix = sdscatprintf(prefix, "!%s", result->name);
            
            if (result->host != NULL) {
                prefix = sdscatprintf(prefix, "@%s", result->host);
            }
        }
    }
    
    return prefix;
}

static inline bool is_numeric_command(char *command) {
    return strlen(command) == 3 && isdigit((int) command[0]) && isdigit((int) command[1]) && isdigit((int) command[2]);
}

static int handle_parser_result (irc_parser *parser, const char *at, size_t len) {
    irc_parser_result_t *result = parser->data;
    irc_session_t *session = result->session;
    
    if (result->command == NULL) {
        return 0;
    }
    
//    print_parser_result(result);
    
    if (is_numeric_command(result->command)) {
        int code = atoi(result->command);
        // We use SESSIONFL_MOTD_RECEIVED flag to check whether it is the first
        // RPL_ENDOFMOTD or ERR_NOMOTD after the connection.
        if ((code == 376 || code == 422) && !(session->flags & SESSIONFL_MOTD_RECEIVED)) {
            session->flags |= SESSIONFL_MOTD_RECEIVED;

            if (session->callbacks.event_connect)
                (*session->callbacks.event_connect) (session, "CONNECT", result);
        }

        if (session->callbacks.event_numeric)
            (*session->callbacks.event_numeric) (session, code, result);
    }
    else {
        char *command = result->command;
        if (result->command == NULL) return 0;

        const irc_command_t *irc_command = get_command(command, strlen(command));
        irc_command->execute(session, command, result);
    }

    return 0;
}

irc_parser* create_line_parser() {
    irc_parser *parser = Calloc(1, sizeof(irc_parser));
    irc_parser_settings parser_settings;
    irc_parser_result_t *parser_result = Calloc(1, sizeof(irc_parser_result_t));
    
    memset(&parser_settings, 0, sizeof (parser_settings));
    
    irc_parser_settings_init(&parser_settings, on_nick, on_name, on_host, on_command, on_param, handle_parser_result, on_error);
    irc_parser_init(parser, &parser_settings);
    
    parser->data = parser_result;
    
    return parser;
}

void line_parser_set_session(irc_parser *parser, irc_session_t *session) {
     irc_parser_result_t *parser_result = parser->data;
     parser_result->session = session;
}
