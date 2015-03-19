#include <stdlib.h>
#include <unistd.h>

char* secure_getenv(const char* name) {
  return issetugid() ? NULL : getenv(name);
}
