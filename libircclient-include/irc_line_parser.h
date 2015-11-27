#ifndef IRC_LINE_PARSER_H
#define	IRC_LINE_PARSER_H

#ifdef	__cplusplus
extern "C" {
#endif
    
#define MAX_PARAMS_ALLOWED 100

struct irc_parser_result_t {
    irc_session_t *session;
    char *nick;
    char *name;
    char *host;
    char *command;
    unsigned int num_params;
    char *params[MAX_PARAMS_ALLOWED+1];
};

typedef struct irc_parser_result_t irc_parser_result_t;

irc_parser* createParser();
void line_parser_set_session(irc_parser *parser, irc_session_t *session);
void free_line_parser(irc_parser *parser);

#ifdef	__cplusplus
}
#endif

#endif

