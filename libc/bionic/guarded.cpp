/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <sys/mman.h>
#include <sys/user.h>

void* __map_guarded(size_t usable_size) {
  size_t real_size = usable_size + PAGE_SIZE * 2;
  if (real_size < usable_size) {
    return MAP_FAILED;
  }
  void* real = mmap(NULL, real_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (real == MAP_FAILED) {
    return real;
  }
  void* usable = reinterpret_cast<char*>(real) + PAGE_SIZE;
  if (mprotect(usable, usable_size, PROT_READ|PROT_WRITE) == -1) {
    munmap(real, real_size);
    return MAP_FAILED;
  }
  return usable;
}

int __unmap_guarded(void* usable, size_t usable_size) {
  void *real = reinterpret_cast<char*>(usable) - PAGE_SIZE;
  return munmap(real, usable_size + PAGE_SIZE * 2);
}
