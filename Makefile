CFLAGS =-std=gnu11 -DENABLE_SSL -DENABLE_IPV6 -Wall -Wfatal-errors -Os -I libircclient-include/
#CFLAGS += -DDEBUG
LIBS = -lssl -lcrypto -lpthread
PROG = xdccget

SRCS = xdccget.c config.c helper.c argument_parser.c libircclient-src/libircclient.c sds.c dirs.c file.c hashing_algo.c sph_md5.c
OBJ_FILES = 

all: gcc

gcc:	$(SRCS)
	gcc $(CFLAGS) -o $(PROG) $(SRCS) $(OBJ_FILES) $(LIBS)

clang:	$(SRCS)
	clang $(CFLAGS) -o $(PROG) $(SRCS) $(OBJ_FILES) $(LIBS)

install:
	cp ./xdccget /usr/bin/

clean:
	rm -f $(PROG)
