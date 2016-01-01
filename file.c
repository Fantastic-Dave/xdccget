#ifdef FILE_API
    #include <stdio.h>
#else
    #include <fcntl.h>
#endif

#include "file.h"

#define FILE_READ_BUFFER_SIZE BUFSIZ

file_io_t* Open(const char *pathname, char *mode) {
    file_io_t *fd = (file_io_t*) malloc(sizeof(file_io_t));
    
#ifdef FILE_API
    fd->fd = NULL;
    if (str_equals(mode, "w")) {
        fd->fd = fopen(pathname, "wb");
    }
    else if (str_equals(mode, "a")) {
        fd->fd = fopen(pathname, "ab");
    }
    else if (str_equals(mode, "r")) {
        fd->fd = fopen(pathname, "rb");
    }
    
    if (fd->fd == NULL) {
        logprintf(LOG_ERR, "Cant open the file %s. Exiting now.", pathname);
        free(fd);
        exitPgm(EXIT_FAILURE);
    }
    
    fd->fileName = pathname;
    fd->mode = mode;
    
    return fd;
#else
    fd->fd = -1;
    
    if (str_equals(mode, "w")) {
        fd->fd = open(pathname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    }
    else if (str_equals(mode, "a")) {
        fd->fd = open(pathname, O_WRONLY | O_APPEND, 0 /*ignored*/);
    }
    else if (str_equals(mode, "r")) {
        fd->fd = open(pathname, O_RDONLY, 0 /*ignored*/);
    }
    
    if (fd->fd == -1) {
        logprintf(LOG_ERR, "Cant open the file %s. Exiting now.", pathname);
        free(fd);
        exitPgm(EXIT_FAILURE);
    }
    
    fd->fileName = pathname;
    fd->mode = mode;
    
    return fd;
#endif
}


void Close(file_io_t *fd) {
    if (fd == NULL)
        return;
#ifdef FILE_API
    if (fd->fd == NULL)
        return;
    int ret = fclose(fd->fd);
    if (ret != 0) {
        logprintf(LOG_ERR, "Cant close the file %s. Exiting now.", fd->fileName);
        exitPgm(EXIT_FAILURE);
    }
#else
    if (fd->fd == -1)
        return;
    int ret = close(fd->fd);
    if (ret == -1) {
        logprintf(LOG_ERR, "Cant close the file %s. Exiting now.", fd->fileName);
        exitPgm(EXIT_FAILURE);
    }
#endif

    free(fd);
}

void Seek(file_io_t *fd, long offset, int whence) {
#ifdef FILE_API
    int ret;
    ret = fseek(fd->fd, offset, whence);
    if (ret == -1) {
        logprintf(LOG_ERR, "Cant fseek the file %s. Exiting now.", fd->fileName);
        exitPgm(EXIT_FAILURE);
    }
#else
    off_t ret;
    ret = lseek(fd->fd, offset, whence);
    if (ret == (off_t) -1) {
        perror("lseek");
        logprintf(LOG_ERR, "Cant lseek the file %s. Exiting now.", fd->fileName);
        exitPgm(EXIT_FAILURE);
    }
#endif
}

void readFile(char *filename, FileReader callback, void *ctx) {
    char buffer[FILE_READ_BUFFER_SIZE+1];
    size_t bytesRead;
    file_io_t *file;

    file = Open(filename, "r");

    do {
        bytesRead = Read(file, buffer, FILE_READ_BUFFER_SIZE);
        callback(buffer, bytesRead, ctx);
    }
    while (bytesRead == FILE_READ_BUFFER_SIZE);

    Close(file);
}
