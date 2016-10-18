/*
 * Copyright (C) 2015 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#undef _FORTIFY_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>
#include "private/libc_logging.h"
#include "private/bionic_globals.h"
#include "pthread_internal.h"

extern "C" size_t __malloc_object_size(const void*);

extern "C" size_t __dynamic_object_size(const void* ptr) {
  if (!__libc_globals->enable_object_size_checks || __get_thread()->in_malloc) {
    return __BIONIC_FORTIFY_UNKNOWN_SIZE;
  }
  return __malloc_object_size(ptr);
}

void __libc_init_dynamic_object_size(libc_globals* globals) {
  globals->enable_object_size_checks = true;
}

ssize_t readlink(const char* path, char* buf, size_t size) {
  return readlinkat(AT_FDCWD, path, buf, size);
}

ssize_t __readlink_chk(const char* path, char* buf, size_t size, size_t buf_size) {
  if (size > __dynamic_object_size(buf)) {
    __fortify_chk_fail("readlink: prevented write past end of buffer", 0);
  }
  return __unchecked___readlink_chk(path, buf, size, buf_size);
}

ssize_t readlinkat(int dirfd, const char* path, char* buf, size_t size) {
  if (size > __dynamic_object_size(buf)) {
    __fortify_chk_fail("readlinkat: prevented write past end of buffer", 0);
  }
  return __unchecked_readlinkat(dirfd, path, buf, size);
}

ssize_t __readlinkat_chk(int dirfd, const char* path, char* buf, size_t size, size_t buf_size) {
  if (size > __dynamic_object_size(buf)) {
    __fortify_chk_fail("readlinkat: prevented write past end of buffer", 0);
  }
  return __unchecked___readlinkat_chk(dirfd, path, buf, size, buf_size);
}

char* getcwd(char* buf, size_t size) {
  if (buf != nullptr && size > __dynamic_object_size(buf)) {
    __fortify_chk_fail("getcwd: prevented write past end of buffer", 0);
  }
  return __unchecked_getcwd(buf, size);
}

char* __getcwd_chk(char* buf, size_t len, size_t buflen) {
  if (buf != nullptr && len > __dynamic_object_size(buf)) {
    __fortify_chk_fail("getcwd: prevented write past end of buffer", 0);
  }
  return __unchecked___getcwd_chk(buf, len, buflen);
}

ssize_t read(int fd, void* buf, size_t count) {
  if (count > __dynamic_object_size(buf)) {
    __fortify_chk_fail("read: prevented write past end of buffer", 0);
  }
  return __unchecked_read(fd, buf, count);
}

ssize_t __read_chk(int fd, void* buf, size_t count, size_t buf_size) {
  if (count > __dynamic_object_size(buf)) {
    __fortify_chk_fail("read: prevented write past end of buffer", 0);
  }
  return __unchecked___read_chk(fd, buf, count, buf_size);
}

ssize_t write(int fd, const void* buf, size_t count) {
  if (count > __dynamic_object_size(buf)) {
    __fortify_chk_fail("write: prevented read past end of buffer", 0);
  }
  return __unchecked_write(fd, buf, count);
}

ssize_t __write_chk(int fd, const void* buf, size_t count, size_t buf_size) {
  if (count > __dynamic_object_size(buf)) {
    __fortify_chk_fail("write: prevented read past end of buffer", 0);
  }
  return __unchecked___write_chk(fd, buf, count, buf_size);
}

ssize_t pread(int fd, void* buf, size_t byte_count, off_t offset) {
  return pread64(fd, buf, byte_count, static_cast<off64_t>(offset));
}

ssize_t pwrite(int fd, const void* buf, size_t byte_count, off_t offset) {
  return pwrite64(fd, buf, byte_count, static_cast<off64_t>(offset));
}

ssize_t pread64(int fd, void* buf, size_t byte_count, off64_t offset) {
  if (byte_count > __dynamic_object_size(buf)) {
    __fortify_chk_fail("pread64: prevented write past end of buffer", 0);
  }
  return __unchecked_pread64(fd, buf, byte_count, offset);
}

ssize_t pwrite64(int fd, const void* buf, size_t byte_count, off64_t offset) {
  if (byte_count > __dynamic_object_size(buf)) {
    __fortify_chk_fail("pwrite64: prevented read past end of buffer", 0);
  }
  return __unchecked_pwrite64(fd, buf, byte_count, offset);
}

ssize_t send(int socket, const void* buf, size_t len, int flags) {
  return sendto(socket, buf, len, flags, nullptr, 0);
}

ssize_t recv(int socket, void *buf, size_t len, int flags) {
  return recvfrom(socket, buf, len, flags, nullptr, 0);
}

ssize_t recvfrom(int fd, void* buf, size_t len, int flags, const struct sockaddr* src_addr, socklen_t* addr_len) {
  if (len > __dynamic_object_size(buf)) {
    __fortify_chk_fail("recvfrom: prevented write past end of buffer", 0);
  }
  return __unchecked_recvfrom(fd, buf, len, flags, src_addr, addr_len);
}

ssize_t __recvfrom_chk(int socket, void* buf, size_t len, size_t buflen,
                       int flags, const struct sockaddr* src_addr,
                       socklen_t* addrlen) {
  if (len > __dynamic_object_size(buf)) {
    __fortify_chk_fail("recvfrom: prevented write past end of buffer", 0);
  }
  return __unchecked___recvfrom_chk(socket, buf, len, buflen, flags, src_addr, addrlen);
}

ssize_t sendto(int fd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addr_len) {
  if (len > __dynamic_object_size(buf)) {
    __fortify_chk_fail("sendto: prevented read past end of buffer", 0);
  }
  return __unchecked_sendto(fd, buf, len, flags, dest_addr, addr_len);
}

ssize_t __sendto_chk(int socket, const void* buf, size_t len, size_t buflen,
                     int flags, const struct sockaddr* dest_addr,
                     socklen_t addrlen) {
  if (len > __dynamic_object_size(buf)) {
    __fortify_chk_fail("sendto: prevented read past end of buffer", 0);
  }
  return __unchecked___sendto_chk(socket, buf, len, buflen, flags, dest_addr, addrlen);
}
