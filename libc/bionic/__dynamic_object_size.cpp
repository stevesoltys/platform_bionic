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
#undef __DISABLE_DYNAMIC_OBJECT_SIZE
#include <fcntl.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>
#include "private/libc_logging.h"

extern "C" size_t __malloc_object_size(const void*);

extern "C" size_t __dynamic_object_size(const void* ptr) {
  return __malloc_object_size(ptr);
}

ssize_t readlink(const char* path, char* buf, size_t size) {
  return readlinkat(AT_FDCWD, path, buf, size);
}

ssize_t readlinkat(int dirfd, const char* path, char* buf, size_t size) {
  if (size > __dynamic_object_size(buf)) {
    __fortify_chk_fail("readlinkat: prevented write past end of buffer", 0);
  }
  return __unchecked_readlinkat(dirfd, path, buf, size);
}

char* getcwd(char* buf, size_t size) {
  if (size > __dynamic_object_size(buf)) {
    __fortify_chk_fail("getcwd: prevented write past end of buffer", 0);
  }
  return __unchecked_getcwd(buf, size);
}

ssize_t read(int fd, void* buf, size_t count) {
  if (count > __dynamic_object_size(buf)) {
    __fortify_chk_fail("read: prevented write past end of buffer", 0);
  }
  return __unchecked_read(fd, buf, count);
}

ssize_t write(int fd, const void* buf, size_t count) {
  if (count > __dynamic_object_size(buf)) {
    __fortify_chk_fail("write: prevented read past end of buffer", 0);
  }
  return __unchecked_write(fd, buf, count);
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
  return sendto(socket, buf, len, flags, NULL, 0);
}

ssize_t recv(int socket, void *buf, size_t len, int flags) {
  return recvfrom(socket, buf, len, flags, NULL, 0);
}

ssize_t recvfrom(int fd, void* buf, size_t len, int flags, const struct sockaddr* src_addr, socklen_t* addr_len) {
  if (len > __dynamic_object_size(buf)) {
    __fortify_chk_fail("recvfrom: prevented write past end of buffer", 0);
  }
  return __unchecked_recvfrom(fd, buf, len, flags, src_addr, addr_len);
}

ssize_t sendto(int fd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addr_len) {
  if (len > __dynamic_object_size(buf)) {
    __fortify_chk_fail("sendto: prevented read past end of buffer", 0);
  }
  return __unchecked_sendto(fd, buf, len, flags, dest_addr, addr_len);
}
