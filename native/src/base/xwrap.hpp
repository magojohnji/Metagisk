#pragma once

#include <string>
#include <dirent.h>
#include <stdio.h>
#include <poll.h>
#include <fcntl.h>

#include "cxx.h"

namespace std {
class source_location {
public:
    // The names source_location::__impl, _M_file_name, _M_function_name, _M_line, and _M_column
    // are hard-coded in the compiler and must not be changed here.
    struct __impl {
        const char *_M_file_name;
        const char *_M_function_name;
        unsigned _M_line;
        unsigned _M_column;
    };
};
}

namespace rust {
using source_location = std::source_location::__impl;
inline String source_to_str(const source_location *source) {
    return source ? std::string(source->_M_file_name) + ":" + std::to_string(source->_M_line) : "??:??";
}
}

#include <base-rs.hpp>

using rust::xpipe2;
extern "C" {

#define SOURCE const void *source_location = __builtin_source_location()

FILE *xfopen(const char *pathname, const char *mode, SOURCE);
FILE *xfdopen(int fd, const char *mode, SOURCE);
int xopen(const char *pathname, int flags, mode_t mode = 0, SOURCE);
int xopenat(int dirfd, const char *pathname, int flags, mode_t mode = 0, SOURCE);
ssize_t xwrite(int fd, const void *buf, size_t count, SOURCE);
ssize_t xread(int fd, void *buf, size_t count, SOURCE);
ssize_t xxread(int fd, void *buf, size_t count, SOURCE);
off64_t xlseek64(int fd, off64_t offset, int whence, SOURCE);
int xsetns(int fd, int nstype, SOURCE);
int xunshare(int flags, SOURCE);
DIR *xopendir(const char *name, SOURCE);
DIR *xfdopendir(int fd, SOURCE);
dirent *xreaddir(DIR *dirp, SOURCE);
pid_t xsetsid(SOURCE);
int xsocket(int domain, int type, int protocol, SOURCE);
int xbind(int sockfd, const struct sockaddr *addr, socklen_t addrlen, SOURCE);
int xlisten(int sockfd, int backlog, SOURCE);
int xaccept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags, SOURCE);
ssize_t xsendmsg(int sockfd, const struct msghdr *msg, int flags, SOURCE);
ssize_t xrecvmsg(int sockfd, struct msghdr *msg, int flags, SOURCE);
int xaccess(const char *path, int mode, SOURCE);
int xfaccessat(int dirfd, const char *pathname, int mode, int flags, SOURCE);
int xstat(const char *pathname, struct stat *buf, SOURCE);
int xlstat(const char *pathname, struct stat *buf, SOURCE);
int xfstat(int fd, struct stat *buf, SOURCE);
int xfstatat(int dirfd, const char *pathname, struct stat *buf, int flags, SOURCE);
int xdup(int fd, SOURCE);
int xdup2(int oldfd, int newfd, SOURCE);
int xdup3(int oldfd, int newfd, int flags, SOURCE);
ssize_t xreadlink(const char * __restrict__ pathname, char * __restrict__ buf, size_t bufsiz, SOURCE);
ssize_t xreadlinkat(
        int dirfd, const char * __restrict__ pathname, char * __restrict__ buf, size_t bufsiz, SOURCE);
int xsymlink(const char *target, const char *linkpath, SOURCE);
int xsymlinkat(const char *target, int newdirfd, const char *linkpath, SOURCE);
int xlinkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags, SOURCE);
int xmount(const char *source, const char *target,
           const char *filesystemtype, unsigned long mountflags,
           const void *data, SOURCE);
int xumount(const char *target, SOURCE);
int xumount2(const char *target, int flags, SOURCE);
int xrename(const char *oldpath, const char *newpath, SOURCE);
int xmkdir(const char *pathname, mode_t mode, SOURCE);
int xmkdirs(const char *pathname, mode_t mode, SOURCE);
int xmkdirat(int dirfd, const char *pathname, mode_t mode, SOURCE);
void *xmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset, SOURCE);
ssize_t xsendfile(int out_fd, int in_fd, off_t *offset, size_t count, SOURCE);
pid_t xfork(SOURCE);
int xpoll(pollfd *fds, nfds_t nfds, int timeout, SOURCE);
ssize_t xrealpath(const char * __restrict__ path, char * __restrict__ buf, size_t bufsiz, SOURCE);
int xmknod(const char * pathname, mode_t mode, dev_t dev, SOURCE);
#undef SOURCE

} // extern "C"
