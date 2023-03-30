use std::ffi::CStr;
use std::os::unix::io::RawFd;
use std::ptr;

use libc::{
    c_char, c_uint, c_ulong, c_void, dev_t, mode_t, nfds_t, off_t, pollfd, sockaddr, socklen_t,
    ssize_t, SYS_dup3,
};

use crate::ffi2::{source_location, source_to_str};
use crate::{cstr, errno, error, mkdirs, perror, ptr_to_str, realpath, serror};

mod unsafe_impl {
    use std::ffi::CStr;
    use std::os::unix::io::RawFd;

    use cfg_if::cfg_if;
    use libc::{c_char, nfds_t, off_t, pollfd};

    use crate::ffi2::source_location;
    use crate::unsafe_impl::readlink;
    use crate::{ptr_to_str, serror, slice_from_ptr, slice_from_ptr_mut};

    #[no_mangle]
    unsafe extern "C" fn xwrite(
        fd: RawFd,
        buf: *const u8,
        bufsz: usize,
        source: *const source_location,
    ) -> isize {
        super::xwrite(fd, slice_from_ptr(buf, bufsz), source)
    }

    #[no_mangle]
    unsafe extern "C" fn xread(
        fd: RawFd,
        buf: *mut u8,
        bufsz: usize,
        source: *const source_location,
    ) -> isize {
        super::xread(fd, slice_from_ptr_mut(buf, bufsz), source)
    }

    #[no_mangle]
    unsafe extern "C" fn xxread(
        fd: RawFd,
        buf: *mut u8,
        bufsz: usize,
        source: *const source_location,
    ) -> isize {
        super::xxread(fd, slice_from_ptr_mut(buf, bufsz), source)
    }

    #[no_mangle]
    unsafe extern "C" fn xrealpath(
        path: *const c_char,
        buf: *mut u8,
        bufsz: usize,
        source: *const source_location,
    ) -> isize {
        super::xrealpath(CStr::from_ptr(path), slice_from_ptr_mut(buf, bufsz), source)
    }

    #[no_mangle]
    pub unsafe extern "C" fn xreadlink(
        path: *const c_char,
        buf: *mut u8,
        bufsz: usize,
        source: *const source_location,
    ) -> isize {
        let r = readlink(path, buf, bufsz);
        if r < 0 {
            serror!(source, "readlink");
        }
        return r;
    }

    #[no_mangle]
    pub unsafe extern "C" fn xreadlinkat(
        dirfd: RawFd,
        path: *const c_char,
        buf: *mut u8,
        bufsz: usize,
        source: *const source_location,
    ) -> isize {
        // readlinkat() may fail on x86 platform, returning random value
        // instead of number of bytes placed in buf (length of link)
        cfg_if! {
            if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                libc::memset(buf.cast(), 0, bufsz);
                let r = libc::readlinkat(dirfd, path, buf.cast(), bufsz - 1);
                if r < 0 {
                    serror!(source, "readlinkat {}", ptr_to_str(path))
                }
            } else {
                let r = libc::readlinkat(dirfd, path, buf.cast(), bufsz - 1);
                if r < 0 {
                    serror!(source, "readlinkat {}", ptr_to_str(path))
                } else {
                    *buf.offset(r) = b'\0';
                }
            }
        }
        return r;
    }

    #[no_mangle]
    pub unsafe extern "C" fn xpoll(
        fds: *mut pollfd,
        nfds: nfds_t,
        timeout: i32,
        source: *const source_location,
    ) -> i32 {
        let r = libc::poll(fds, nfds, timeout);
        if r < 0 {
            serror!(source, "poll");
        }
        return r;
    }

    #[no_mangle]
    pub unsafe extern "C" fn xsendfile(
        out_fd: RawFd,
        in_fd: RawFd,
        offset: *mut off_t,
        count: usize,
        source: *const source_location,
    ) -> isize {
        let r = libc::sendfile(out_fd, in_fd, offset, count);
        if r < 0 {
            serror!(source, "sendfile");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xfopen(
    path: *const c_char,
    mode: *const c_char,
    source: *const source_location,
) -> *mut libc::FILE {
    unsafe {
        let fp = libc::fopen(path, mode);
        if fp.is_null() {
            serror!(source, "fopen {}", ptr_to_str(path));
        }
        return fp;
    }
}

#[no_mangle]
pub extern "C" fn xfdopen(
    fd: RawFd,
    mode: *const c_char,
    source: *const source_location,
) -> *mut libc::FILE {
    unsafe {
        let fp = libc::fdopen(fd, mode);
        if fp.is_null() {
            serror!(source, "fdopen");
        }
        return fp;
    }
}

#[no_mangle]
pub extern "C" fn xopen(
    path: *const c_char,
    flags: i32,
    mode: mode_t,
    source: *const source_location,
) -> RawFd {
    unsafe {
        let r = libc::open(path, flags, mode as c_uint);
        if r < 0 {
            serror!(source, "open {}", ptr_to_str(path));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xopenat(
    dirfd: RawFd,
    path: *const c_char,
    flags: i32,
    mode: mode_t,
    source: *const source_location,
) -> RawFd {
    unsafe {
        let r = libc::openat(dirfd, path, flags, mode as c_uint);
        if r < 0 {
            serror!(source, "openat {}", ptr_to_str(path));
        }
        return r;
    }
}

// Fully write data slice
pub fn xwrite(fd: RawFd, data: &[u8], source: *const source_location) -> isize {
    unsafe {
        let mut write_sz: usize = 0;
        let mut r: ssize_t;
        let mut remain: &[u8] = data;
        loop {
            r = libc::write(fd, remain.as_ptr().cast(), remain.len());
            if r < 0 {
                if *errno() == libc::EINTR {
                    continue;
                }
                serror!(source, "write");
                return r as isize;
            }
            let r = r as usize;
            write_sz += r;
            remain = &remain[r..];
            if r == 0 || remain.len() == 0 {
                break;
            }
        }
        if remain.len() != 0 {
            error!(
                "{}: write ({} != {})",
                source_to_str(source),
                write_sz,
                data.len()
            )
        }
        return write_sz as isize;
    }
}

pub fn xread(fd: RawFd, data: &mut [u8], source: *const source_location) -> isize {
    unsafe {
        let r = libc::read(fd, data.as_mut_ptr().cast(), data.len());
        if r < 0 {
            serror!(source, "read");
        }
        return r;
    }
}

// Fully read size of data slice
pub fn xxread(fd: RawFd, data: &mut [u8], source: *const source_location) -> isize {
    unsafe {
        let mut read_sz: usize = 0;
        let mut r: ssize_t;
        let mut remain: &mut [u8] = data;
        loop {
            r = libc::read(fd, remain.as_mut_ptr().cast(), remain.len());
            if r < 0 {
                if *errno() == libc::EINTR {
                    continue;
                }
                serror!(source, "read");
                return r as isize;
            }
            let r = r as usize;
            read_sz += r;
            remain = &mut remain[r..];
            if r == 0 || remain.len() == 0 {
                break;
            }
        }
        if remain.len() != 0 {
            error!(
                "{}: read ({} != {})",
                source_to_str(source),
                read_sz,
                data.len()
            )
        }
        return read_sz as isize;
    }
}

#[no_mangle]
pub extern "C" fn xlseek64(
    fd: RawFd,
    offset: i64,
    whence: i32,
    source: *const source_location,
) -> i64 {
    unsafe {
        let r = libc::lseek64(fd, offset, whence);
        if r < 0 {
            serror!(source, "lseek64");
        }
        return r;
    }
}

pub fn xpipe2(fds: &mut [i32; 2], flags: i32) -> i32 {
    unsafe {
        let r = libc::pipe2(fds.as_mut_ptr(), flags);
        if r < 0 {
            perror!("pipe2");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xsetns(fd: RawFd, nstype: i32, source: *const source_location) -> i32 {
    unsafe {
        let r = libc::setns(fd, nstype);
        if r < 0 {
            serror!(source, "setns");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xunshare(flags: i32, source: *const source_location) -> i32 {
    unsafe {
        let r = libc::unshare(flags);
        if r < 0 {
            serror!(source, "unshare");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xopendir(path: *const c_char, source: *const source_location) -> *mut libc::DIR {
    unsafe {
        let dp = libc::opendir(path);
        if dp.is_null() {
            serror!(source, "opendir {}", ptr_to_str(path));
        }
        return dp;
    }
}

#[no_mangle]
pub extern "C" fn xfdopendir(fd: RawFd, source: *const source_location) -> *mut libc::DIR {
    unsafe {
        let dp = libc::fdopendir(fd);
        if dp.is_null() {
            serror!(source, "fdopendir");
        }
        return dp;
    }
}

#[no_mangle]
pub extern "C" fn xreaddir(
    dirp: *mut libc::DIR,
    source: *const source_location,
) -> *mut libc::dirent {
    #[allow(unused_unsafe)]
    unsafe {
        *errno() = 0;
        loop {
            let e = libc::readdir(dirp);
            if e.is_null() {
                if *errno() != 0 {
                    serror!(source, "readdir")
                }
            } else {
                // Filter out . and ..
                let s = CStr::from_ptr((*e).d_name.as_ptr());
                if s == cstr!(".") || s == cstr!("..") {
                    continue;
                }
            };
            return e;
        }
    }
}

#[no_mangle]
pub extern "C" fn xsetsid(source: *const source_location) -> i32 {
    unsafe {
        let r = libc::setsid();
        if r < 0 {
            serror!(source, "setsid");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xsocket(
    domain: i32,
    ty: i32,
    protocol: i32,
    source: *const source_location,
) -> RawFd {
    unsafe {
        let fd = libc::socket(domain, ty, protocol);
        if fd < 0 {
            serror!(source, "socket");
        }
        return fd;
    }
}

#[no_mangle]
pub extern "C" fn xbind(
    socket: i32,
    address: *const sockaddr,
    len: socklen_t,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::bind(socket, address, len);
        if r < 0 {
            serror!(source, "bind");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xlisten(socket: i32, backlog: i32, source: *const source_location) -> i32 {
    unsafe {
        let r = libc::listen(socket, backlog);
        if r < 0 {
            serror!(source, "listen");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xaccept4(
    sockfd: RawFd,
    addr: *mut sockaddr,
    len: *mut socklen_t,
    flg: i32,
    source: *const source_location,
) -> RawFd {
    unsafe {
        let fd = libc::accept4(sockfd, addr, len, flg);
        if fd < 0 {
            serror!(source, "accept4");
        }
        return fd;
    }
}

#[no_mangle]
pub extern "C" fn xsendmsg(
    fd: RawFd,
    msg: *const libc::msghdr,
    flags: i32,
    source: *const source_location,
) -> ssize_t {
    unsafe {
        let r = libc::sendmsg(fd, msg, flags);
        if r < 0 {
            serror!(source, "sendmsg");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xrecvmsg(
    fd: RawFd,
    msg: *mut libc::msghdr,
    flags: i32,
    source: *const source_location,
) -> ssize_t {
    unsafe {
        let r = libc::recvmsg(fd, msg, flags);
        if r < 0 {
            serror!(source, "recvmsg");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xaccess(path: *const c_char, mode: i32, source: *const source_location) -> i32 {
    unsafe {
        let r = libc::access(path, mode);
        if r < 0 {
            serror!(source, "access {}", ptr_to_str(path));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xfaccessat(
    dirfd: RawFd,
    path: *const c_char,
    mode: i32,
    flags: i32,
    source: *const source_location,
) -> i32 {
    unsafe {
        #[allow(unused_mut)]
        let mut r = libc::faccessat(dirfd, path, mode, flags);
        if r < 0 {
            serror!(source, "faccessat {}", ptr_to_str(path));
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if r > 0 && *errno() == 0 {
            r = 0
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xstat(
    path: *const c_char,
    buf: *mut libc::stat,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::stat(path, buf);
        if r < 0 {
            serror!(source, "stat {}", ptr_to_str(path));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xlstat(
    path: *const c_char,
    buf: *mut libc::stat,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::lstat(path, buf);
        if r < 0 {
            serror!(source, "lstat {}", ptr_to_str(path));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xfstat(fd: RawFd, buf: *mut libc::stat, source: *const source_location) -> i32 {
    unsafe {
        let r = libc::fstat(fd, buf);
        if r < 0 {
            serror!(source, "fstat");
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xfstatat(
    dirfd: RawFd,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: i32,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::fstatat(dirfd, path, buf, flags);
        if r < 0 {
            serror!(source, "fstatat {}", ptr_to_str(path));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xdup(oldfd: RawFd, source: *const source_location) -> RawFd {
    unsafe {
        let fd = libc::dup(oldfd);
        if fd < 0 {
            serror!(source, "dup");
        }
        return fd;
    }
}

#[no_mangle]
pub extern "C" fn xdup2(oldfd: RawFd, newfd: RawFd, source: *const source_location) -> RawFd {
    unsafe {
        let fd = libc::dup2(oldfd, newfd);
        if fd < 0 {
            serror!(source, "dup2");
        }
        return fd;
    }
}

#[no_mangle]
pub extern "C" fn xdup3(
    oldfd: RawFd,
    newfd: RawFd,
    flags: i32,
    source: *const source_location,
) -> RawFd {
    unsafe {
        let fd = libc::syscall(SYS_dup3, oldfd, newfd, flags) as RawFd;
        if fd < 0 {
            serror!(source, "dup3");
        }
        return fd;
    }
}

#[inline]
pub fn xreadlink(path: &CStr, data: &mut [u8], source: *const source_location) -> isize {
    unsafe { unsafe_impl::xreadlink(path.as_ptr(), data.as_mut_ptr(), data.len(), source) }
}

#[inline]
pub fn xreadlinkat(
    dirfd: RawFd,
    path: &CStr,
    data: &mut [u8],
    source: *const source_location,
) -> isize {
    unsafe { unsafe_impl::xreadlinkat(dirfd, path.as_ptr(), data.as_mut_ptr(), data.len(), source) }
}

#[no_mangle]
pub extern "C" fn xsymlink(
    target: *const c_char,
    linkpath: *const c_char,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::symlink(target, linkpath);
        if r < 0 {
            serror!(
                source,
                "symlink {} -> {}",
                ptr_to_str(target),
                ptr_to_str(linkpath)
            );
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xsymlinkat(
    target: *const c_char,
    dirfd: RawFd,
    linkpath: *const c_char,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::symlinkat(target, dirfd, linkpath);
        if r < 0 {
            serror!(
                source,
                "symlinkat {} -> {}",
                ptr_to_str(target),
                ptr_to_str(linkpath)
            );
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xlinkat(
    olddirfd: RawFd,
    target: *const c_char,
    newdirfd: RawFd,
    linkpath: *const c_char,
    flags: i32,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::linkat(olddirfd, target, newdirfd, linkpath, flags);
        if r < 0 {
            serror!(
                source,
                "linkat {} -> {}",
                ptr_to_str(target),
                ptr_to_str(linkpath)
            );
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xmount(
    src: *const c_char,
    target: *const c_char,
    fstype: *const c_char,
    flags: c_ulong,
    data: *const c_void,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::mount(src, target, fstype, flags, data);
        if r < 0 {
            serror!(
                source,
                "mount {} -> {}",
                ptr_to_str(src),
                ptr_to_str(target)
            );
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xumount(target: *const c_char, source: *const source_location) -> i32 {
    unsafe {
        let r = libc::umount(target);
        if r < 0 {
            serror!(source, "umount {}", ptr_to_str(target));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xumount2(
    target: *const c_char,
    flags: i32,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::umount2(target, flags);
        if r < 0 {
            serror!(source, "umount2 {}", ptr_to_str(target));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xrename(
    oldname: *const c_char,
    newname: *const c_char,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::rename(oldname, newname);
        if r < 0 {
            serror!(
                source,
                "rename {} -> {}",
                ptr_to_str(oldname),
                ptr_to_str(newname)
            );
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xmkdir(path: *const c_char, mode: mode_t, source: *const source_location) -> i32 {
    unsafe {
        let r = libc::mkdir(path, mode);
        if r < 0 && *errno() != libc::EEXIST {
            serror!(source, "mkdir {}", ptr_to_str(path));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xmkdirs(path: *const c_char, mode: mode_t) -> i32 {
    let r = mkdirs(path, mode);
    if r < 0 {
        perror!("mkdirs {}", ptr_to_str(path));
    }
    return r;
}

#[no_mangle]
pub extern "C" fn xmkdirat(dirfd: RawFd, path: *const c_char, mode: mode_t) -> i32 {
    unsafe {
        let r = libc::mkdirat(dirfd, path, mode);
        if r < 0 && *errno() != libc::EEXIST {
            perror!("mkdirat {}", ptr_to_str(path));
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xmmap(
    addr: *mut c_void,
    len: usize,
    prot: i32,
    flags: i32,
    fd: RawFd,
    offset: off_t,
    source: *const source_location,
) -> *mut c_void {
    unsafe {
        let r = libc::mmap(addr, len, prot, flags, fd, offset);
        if r == libc::MAP_FAILED {
            serror!(source, "mmap");
            return ptr::null_mut();
        }
        return r;
    }
}

#[inline]
pub fn xsendfile(
    out_fd: RawFd,
    in_fd: RawFd,
    offset: Option<&mut off_t>,
    count: usize,
    source: *const source_location,
) -> isize {
    unsafe {
        let p = offset.map_or(ptr::null_mut(), |it| it);
        unsafe_impl::xsendfile(out_fd, in_fd, p, count, source)
    }
}

#[no_mangle]
pub extern "C" fn xfork(source: *const source_location) -> i32 {
    unsafe {
        let r = libc::fork();
        if r < 0 {
            serror!(source, "fork");
        }
        return r;
    }
}

#[inline]
pub fn xpoll(fds: &mut [pollfd], timeout: i32, source: *const source_location) -> i32 {
    unsafe { unsafe_impl::xpoll(fds.as_mut_ptr(), fds.len() as nfds_t, timeout, source) }
}

pub fn xrealpath(path: &CStr, buf: &mut [u8], source: *const source_location) -> isize {
    unsafe {
        let r = realpath(path, buf);
        if r < 0 {
            serror!(source, "realpath {}", path.to_str().unwrap_or(""))
        }
        return r;
    }
}

#[no_mangle]
pub extern "C" fn xmknod(
    pathname: *const c_char,
    mode: mode_t,
    dev: dev_t,
    source: *const source_location,
) -> i32 {
    unsafe {
        let r = libc::mknod(pathname, mode, dev);
        if r < 0 {
            serror!(source, "mknod {}", ptr_to_str(pathname));
        }
        return r;
    }
}
