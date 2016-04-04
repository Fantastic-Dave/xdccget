#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>

#include "fd_watcher.h"
#include "../helper.h"

static int nfiles;
static long nwatches;
static uint8_t* fd_rw;
static int nreturned, next_ridx;

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifdef HAVE_POLL
#include <poll.h>
#endif

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef HAVE_POLL

#define WHICH "poll"
#define INIT(nf) poll_init(nf)
#define ADD_FD(fd) poll_add_fd(fd)
#define DEL_FD(fd) poll_del_fd(fd)
#define SET_FD(fd, rw) poll_set_fd(fd, rw)
#define ZERO_FDS() poll_zero();
#define WATCH(timeout_msecs) poll_watch(timeout_msecs)
#define CHECK_FD(fd, rw) poll_check_fd(fd, rw)
#define FREE_FD_WATCHER() poll_free();

static int poll_init(int nf);
static void poll_add_fd(int fd);
static void poll_del_fd(int fd);
static int poll_watch(long timeout_msecs);
static int poll_check_fd(int fd, uint8_t rw);
static void poll_set_fd(int fd, uint8_t rw);
static void poll_zero();
static void poll_free();

#endif

#ifdef HAVE_EPOLL
#define WHICH "epoll"
#define INIT(nf) epoll_init(nf)
#define ADD_FD(fd) epoll_add_fd(fd)
#define DEL_FD(fd) epoll_del_fd(fd)
#define SET_FD(fd, rw) epoll_set_fd(fd, rw)
#define ZERO_FDS() epoll_zero();
#define WATCH(timeout_msecs) epoll_watch(timeout_msecs)
#define CHECK_FD(fd, rw) epoll_check_fd(fd, rw)
#define FREE_FD_WATCHER() epoll_free();


static int epoll_init(int nf);
static void epoll_add_fd(int fd);
static void epoll_del_fd(int fd);
static int epoll_watch(long timeout_msecs);
static int epoll_check_fd(int fd, uint8_t rw);
static void epoll_set_fd(int fd, uint8_t rw);
static void epoll_zero();
static void epoll_free();
#endif

#ifdef HAVE_SELECT

#define WHICH "select"
#define INIT(nf) select_init(nf)
#define ADD_FD(fd) select_add_fd(fd)
#define DEL_FD(fd) select_del_fd(fd)
#define SET_FD(fd, rw) select_set_fd(fd, rw)
#define ZERO_FDS() select_zero();
#define WATCH(timeout_msecs) select_watch(timeout_msecs)
#define CHECK_FD(fd, rw) select_check_fd(fd, rw)
#define FREE_FD_WATCHER() select_free();

static int select_init(int nf);
static void select_add_fd(int fd);
static void select_del_fd(int fd);
static int select_watch(long timeout_msecs);
static int select_check_fd(int fd, uint8_t rw);
static void select_set_fd(int fd, uint8_t rw);
static void select_zero();
static void select_free();
#endif

/* Routines. */

/* Figure out how many file descriptors the system allows, and
 ** initialize the fdwatch data structures.  Returns -1 on failure.
 */
int fdwatch_init()
{
    int i;
#ifdef RLIMIT_NOFILE
    struct rlimit rl;
#endif /* RLIMIT_NOFILE */

    /* Figure out how many fd's we can have. */
    nfiles = getdtablesize();
#ifdef RLIMIT_NOFILE
    /* If we have getrlimit(), use that, and attempt to raise the limit. */
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        nfiles = rl.rlim_cur;
        if (rl.rlim_max == RLIM_INFINITY)
            rl.rlim_cur = 8192; /* arbitrary */
        else if (rl.rlim_max > rl.rlim_cur)
            rl.rlim_cur = rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rl) == 0)
            nfiles = rl.rlim_cur;
    }
#endif /* RLIMIT_NOFILE */

#if defined(HAVE_SELECT) && !(defined(HAVE_POLL) || defined(HAVE_DEVPOLL) || defined(HAVE_KQUEUE))
    /* If we use select(), then we must limit ourselves to FD_SETSIZE. */
    nfiles = MIN(nfiles, FD_SETSIZE);
#endif /* HAVE_SELECT && ! ( HAVE_POLL || HAVE_DEVPOLL || HAVE_KQUEUE ) */

    /* Initialize the fdwatch data structures. */
    nwatches = 0;
    fd_rw = (uint8_t*)malloc(sizeof(uint8_t) * nfiles);
    if (fd_rw == NULL)
        return -1;
    for (i = 0; i < nfiles; ++i)
        fd_rw[i] = 0;
    if (INIT(nfiles) == -1)
        return -1;

    return nfiles;
}

void fdwatch_free() {
    free(fd_rw);
    FREE_FD_WATCHER();
}

/* Add a descriptor to the watch list.  rw is either FDW_READ or FDW_WRITE.  */
void fdwatch_add_fd(int fd)
{
    if (fd < 0 || fd >= nfiles) {
        logprintf(LOG_ERR, "bad fd (%d) passed to fdwatch_add_fd!", fd);
        return;
    }

    ADD_FD(fd);
}

/* Remove a descriptor from the watch list. */
void fdwatch_del_fd(int fd)
{
    if (fd < 0 || fd >= nfiles) {
        logprintf(LOG_ERR, "bad fd (%d) passed to fdwatch_del_fd!", fd);
        return;
    }

    DEL_FD(fd);
    fd_rw[fd] = 0;
}

void fdwatch_set_fd(int fd, uint8_t rw)
{
    if (fd < 0 || fd >= nfiles) {
        logprintf(LOG_ERR, "bad fd (%d) passed to fdwatch_set_fd!", fd);
        return;
    }

    SET_FD(fd, rw);
}

void fdwatch_zero() { ZERO_FDS(); }

/* Do the watch.  Return value is the number of descriptors that are ready,
 ** or 0 if the timeout expired, or -1 on errors.  A timeout of INFTIM means
 ** wait indefinitely.
 */
int fdwatch(long timeout_msecs)
{
    ++nwatches;
    nreturned = WATCH(timeout_msecs);
    next_ridx = 0;
    return nreturned;
}

/* Check if a descriptor was ready. */
int fdwatch_check_fd(int fd, uint8_t rw)
{
    if (fd < 0 || fd >= nfiles) {
        logprintf(LOG_ERR, "bad fd (%d) passed to fdwatch_check_fd!", fd);
        return 0;
    }
    return CHECK_FD(fd, rw);
}

/* Generate debugging statistics syslog message. */
void fdwatch_logstats(long secs)
{
    if (secs > 0)
        logprintf(LOG_INFO, "  fdwatch - %ld %ss (%g/sec)", nwatches, WHICH,
            (float)nwatches / secs);
    nwatches = 0;
}

#ifdef HAVE_POLL

static struct pollfd* pollfds;
static int npoll_fds;
static int* poll_fdidx;
static int* poll_rfdidx;

static void poll_zero_out(int nf)
{
    for (int i = 0; i < nf; ++i) {
        pollfds[i].fd = poll_fdidx[i] = -1;
        pollfds[i].events = 0;
        pollfds[i].revents = 0;
    }
}

static int poll_init(int nf)
{
    pollfds = malloc(sizeof(struct pollfd) * nf);
    poll_fdidx = malloc(sizeof(int) * nf);
    poll_rfdidx = malloc(sizeof(int) * nf);

    if (pollfds == (struct pollfd*)0 || poll_fdidx == (int*)0 || poll_rfdidx == (int*)0)
        return -1;

    poll_zero_out(nf);
    return 0;
}


static void poll_free() {
    free(pollfds);
    free(poll_fdidx);
    free(poll_rfdidx);
}

static void poll_add_fd(int fd)
{
    if (npoll_fds >= nfiles) {
        logprintf(LOG_ERR, "too many fds in poll_add_fd!");
        return;
    }

    pollfds[npoll_fds].fd = fd;
    poll_fdidx[fd] = npoll_fds;
    ++npoll_fds;
}

static void poll_del_fd(int fd)
{
    int idx = poll_fdidx[fd];

    if (idx < 0 || idx >= nfiles) {
        logprintf(LOG_ERR, "bad idx (%d) in poll_del_fd!", idx);
        return;
    }
    --npoll_fds;
    pollfds[idx].events = 0;
    pollfds[idx].revents = 0;
    pollfds[idx] = pollfds[npoll_fds];
    poll_fdidx[pollfds[idx].fd] = idx;
    pollfds[npoll_fds].fd = -1;
    poll_fdidx[fd] = -1;
}

static void poll_set_fd(int fd, uint8_t rw)
{
    int fdidx = poll_fdidx[fd];

    switch (rw) {
    case FDW_READ:
        pollfds[fdidx].events |= POLLIN;
        break;
    case FDW_WRITE:
        pollfds[fdidx].events |= POLLOUT;
        break;
    }
}

static void poll_zero()
{
    poll_zero_out(npoll_fds);
    npoll_fds = 0;
}

static int poll_watch(long timeout_msecs)
{
    int r;

    r = poll(pollfds, npoll_fds, (int)timeout_msecs);
    if (r <= 0)
        return r;

    return r;
}

static int poll_check_fd(int fd, uint8_t rw)
{
    int fdidx = poll_fdidx[fd];

    if (fdidx < 0 || fdidx >= nfiles) {
        logprintf(LOG_ERR, "bad fdidx (%d) in poll_check_fd!", fdidx);
        return 0;
    }
    if (pollfds[fdidx].revents & POLLERR) {
        return 0;
    }

    switch (rw) {
    case FDW_READ:
        return pollfds[fdidx].revents & (POLLIN);
    case FDW_WRITE:
        return pollfds[fdidx].revents & (POLLOUT);
    }

    return 0;
}

#endif

#ifdef HAVE_EPOLL

static int max_events = -1;
static struct epoll_event* events;
static struct epoll_event* resulting_events;
static int npoll_fds;
static int* poll_fdidx;
static int epoll_fd = -1;
static int watched_events = -1;

static void epoll_zero_out(int nf)
{
    for (int i = 0; i < nf; i++) {
        poll_fdidx[i] = -1;
        events[i].events = 0;
    }
}

static int epoll_init(int nf)
{
    events = malloc(sizeof(struct epoll_event) * nf);
    resulting_events = malloc(sizeof(struct epoll_event) * nf);
    poll_fdidx = malloc(sizeof(int) * nf);
    max_events = nf;

    if (events == NULL || poll_fdidx == NULL)
        return -1;
    
    epoll_fd = epoll_create1(0);
    
    if (epoll_fd == -1) {
        return -1;
    }
    
    epoll_zero_out(nf);
    return 0;
}

static void epoll_free() {
    free(events);
    free(resulting_events);
    free(poll_fdidx);
    close(epoll_fd);
}

static void epoll_add_fd(int fd)
{
    if (npoll_fds >= nfiles) {
        logprintf(LOG_ERR, "too many fds in poll_add_fd!");
        return;
    }

    events[npoll_fds].data.fd = fd;
    events[npoll_fds].events = 0;
    int ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &events[npoll_fds]);
    if (ret == -1) {
        DBG_WARN("epoll_ctl failed with fd = %d", fd);
        return;
    }
    poll_fdidx[fd] = npoll_fds;
    ++npoll_fds;
}

static void epoll_del_fd(int fd)
{
    int idx = poll_fdidx[fd];

    if (idx < 0 || idx >= nfiles) {
        logprintf(LOG_ERR, "bad idx (%d) in poll_del_fd!", idx);
        return;
    }
    
    int ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &events[idx]);
    if (ret == -1) {
        DBG_WARN("epoll_ctl failed with fd = %d", fd);
        return;
    }
    
    --npoll_fds;
    events[idx].data.fd = -1;
    poll_fdidx[fd] = -1;
}

static void epoll_set_fd(int fd, uint8_t rw)
{
    int fdidx = poll_fdidx[fd];

    switch (rw) {
    case FDW_READ:
        events[fdidx].events |= EPOLLIN | EPOLLET;
        break;
    case FDW_WRITE:
        events[fdidx].events |= EPOLLOUT;
        break;
    }
    
    int ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &events[fdidx]);
    if (ret == -1) {
        DBG_WARN("epoll_ctl failed with fd = %d", fd);
        return;
    }
    
}

static void epoll_zero()
{
    epoll_zero_out(npoll_fds);
    npoll_fds = 0;
}

static int epoll_watch(long timeout_msecs)
{
    watched_events = epoll_wait(epoll_fd, resulting_events, max_events, (int)timeout_msecs);
    return watched_events;
}

static int epoll_check_fd(int fd, uint8_t rw)
{
    int fdidx = poll_fdidx[fd];

    if (fdidx < 0 || fdidx >= nfiles) {
        logprintf(LOG_ERR, "bad fdidx (%d) in poll_check_fd!", fdidx);
        return 0;
    }
    
    for (int i = 0; i < watched_events; i++) {
        if (resulting_events[i].data.fd == fd) {
            switch (rw) {
                case FDW_READ:
                    return resulting_events[i].events & (EPOLLIN);
                case FDW_WRITE:
                    return resulting_events[i].events & (EPOLLOUT);
                }
            }
    }

    return 0;
}

#endif

#ifdef HAVE_SELECT

static fd_set master_rfdset;
static fd_set master_wfdset;
static fd_set working_rfdset;
static fd_set working_wfdset;
static int* select_fds;
static int* select_fdidx;
static int* select_rfdidx;
static int nselect_fds;
static int maxfd;
static int maxfd_changed;

static int select_init(int nf)
{
    int i;

    FD_ZERO(&master_rfdset);
    FD_ZERO(&master_wfdset);
    select_fds = (int*)malloc(sizeof(int) * nf);
    select_fdidx = (int*)malloc(sizeof(int) * nf);
    select_rfdidx = (int*)malloc(sizeof(int) * nf);
    if (select_fds == (int*)0 || select_fdidx == (int*)0 || select_rfdidx == (int*)0)
        return -1;
    nselect_fds = 0;
    maxfd = -1;
    maxfd_changed = 0;
    for (i = 0; i < nf; ++i)
        select_fds[i] = select_fdidx[i] = -1;
    return 0;
}

static void select_free() {
    free(select_fds);
    free(select_fdidx);
    free(select_rfdidx);
}

static void select_add_fd(int fd)
{
    if (nselect_fds >= nfiles) {
        logprintf(LOG_ERR,
            "too many fds in select_add_fd, nfiles = %d, nselect_fds = %d!",
            nfiles, nselect_fds);
        return;
    }
    select_fds[nselect_fds] = fd;

    if (fd > maxfd)
        maxfd = fd;

    select_fdidx[fd] = nselect_fds;
    ++nselect_fds;
}

static void select_set_fd(int fd, uint8_t rw)
{
    switch (rw) {
    case FDW_READ:
        FD_SET(fd, &master_rfdset);
        break;
    case FDW_WRITE:
        FD_SET(fd, &master_wfdset);
        break;
    }
}

static void select_zero()
{
    FD_ZERO(&master_rfdset);
    FD_ZERO(&master_wfdset);
    nselect_fds = 0;
    maxfd_changed = 0;
    maxfd = -1;
}

static void select_del_fd(int fd)
{
    int idx = select_fdidx[fd];

    if (idx < 0 || idx >= nfiles) {
        logprintf(LOG_ERR, "bad idx (%d) in select_del_fd!", idx);
        return;
    }

    --nselect_fds;
    select_fds[idx] = select_fds[nselect_fds];
    select_fdidx[select_fds[idx]] = idx;
    select_fds[nselect_fds] = -1;
    select_fdidx[fd] = -1;

    FD_CLR(fd, &master_rfdset);
    FD_CLR(fd, &master_wfdset);

    if (fd >= maxfd)
        maxfd_changed = 1;
}

static int select_get_maxfd(void)
{
    if (maxfd_changed) {
        int i;
        maxfd = -1;
        for (i = 0; i < nselect_fds; ++i)
            if (select_fds[i] > maxfd)
                maxfd = select_fds[i];
        maxfd_changed = 0;
    }
    return maxfd;
}

static int select_watch(long timeout_msecs)
{
    int mfd;
    int r;

    working_rfdset = master_rfdset;
    working_wfdset = master_wfdset;
    mfd = select_get_maxfd();
    if (timeout_msecs == INFTIM)
        r = select(mfd + 1, &working_rfdset, &working_wfdset, (fd_set*)0,
            (struct timeval*)0);
    else {
        struct timeval timeout;
        timeout.tv_sec = timeout_msecs / 1000L;
        timeout.tv_usec = (timeout_msecs % 1000L) * 1000L;
        r = select(mfd + 1, &working_rfdset, &working_wfdset, (fd_set*)0,
            &timeout);
    }
    if (r <= 0)
        return r;

    return r; /* should be equal to r */
}

static int select_check_fd(int fd, uint8_t rw)
{
    switch (rw) {
    case FDW_READ:
        return FD_ISSET(fd, &working_rfdset);
        break;
    case FDW_WRITE:
        return FD_ISSET(fd, &working_wfdset);
        break;
    }

    return 0;
}

#endif
