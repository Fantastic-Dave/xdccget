
#ifndef FD_WATCHER_H
#define FD_WATCHER_H

#ifdef __cplusplus
extern "C" {
#endif

#define HAVE_EPOLL

#define FDW_READ 0x01
#define FDW_WRITE 0x02

#ifndef INFTIM
#define INFTIM -1
#endif

int fdwatch_init();

void fdwatch_add_fd(int fd);

void fdwatch_del_fd(int fd);

void fdwatch_zero();

void fdwatch_set_fd(int fd, uint8_t rw);

int fdwatch(long timeout_msecs);

int fdwatch_check_fd(int fd, uint8_t rw);

void fdwatch_logstats(long secs);

#ifdef __cplusplus
}
#endif

#endif
