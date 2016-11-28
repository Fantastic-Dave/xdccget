#ifndef FILE_H
#define	FILE_H

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>

#include "helper.h"

struct file_io_t {
#ifdef FILE_API
    FILE *fd;
#else
    int fd;
#endif
    const char *fileName;
    char *mode;
};    

typedef struct file_io_t file_io_t;
typedef void (*FileReader) (void *buffer, unsigned int bytesRead, void *ctx);

static inline bool file_exists(char *file) {
    int ret = access( file, F_OK );
    return ret == 0;
}

static inline bool dir_exists(char *dir) {
    struct stat s;
    int err = stat(dir, &s);
    
    if (err == -1) {
        if (errno == ENOENT) {
            return false;
        }
        
        perror("stat");
        return false;
    }
    
    if(S_ISDIR(s.st_mode)) {
        return true;
    }
    
    return false;
}

static inline off_t get_file_size(char *filename){
    struct stat st;
    
    if (stat(filename, &st) != 0) {
        logprintf(LOG_ERR, "Cant stat the file %s. Exiting now.", filename);
        exitPgm(EXIT_FAILURE);
    }
    
    return st.st_size;
}

#ifdef FILE_API
static inline size_t Read (file_io_t *fd, void *buf, size_t count) {
#else
static inline ssize_t Read (file_io_t *fd, void *buf, ssize_t count) {
#endif
#ifdef FILE_API
    size_t readBytes = fread(buf, 1, count, fd->fd);
    return readBytes;
#else
    ssize_t readBytes = 0;

    do {
        ssize_t ret = read(fd->fd, buf + readBytes, count-readBytes);
        if (unlikely(ret == -1)) {
            logprintf(LOG_ERR, "Cant read the file %s. Exiting now.", fd->fileName);
            exitPgm(EXIT_FAILURE);
        }
        else if (ret == 0) {
            return readBytes;
        }

        readBytes += ret;
    } while (readBytes < count);

    return readBytes;
#endif
}

#ifdef FILE_API
static inline void Write(file_io_t *fd, const void *buf, size_t count) {
#else
  static inline void Write(file_io_t *fd, const void *buf, ssize_t count) {
#endif
#ifdef FILE_API
    size_t written = fwrite(buf, 1, count, fd->fd);
    if (unlikely(written != count)) {
        logprintf(LOG_ERR, "Cant write the file %s. Exiting now.", fd->fileName);
        exitPgm(EXIT_FAILURE);
    }
#else
    ssize_t written = 0;
    do {
        ssize_t ret = write(fd->fd, buf + written, count-written);
        written += ret;
        if (unlikely(ret == -1)) {
            logprintf(LOG_ERR, "Cant write the file %s. Exiting now.", fd->fileName);
            exitPgm(EXIT_FAILURE);
        }
    } while(written < count);
#endif
}
    
file_io_t* Open(const char *pathname, char *mode);
void Close(file_io_t *fd);
void Seek(file_io_t *fd, long offset, int whence);
void readFile(char *filename, FileReader callback, void *ctx);

#endif	/* FILE_H */

