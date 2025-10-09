CC = cc
AR = ar
CFLAGS = -fPIC -Wall -Wextra -O0 -g
LDFLAGS = -shared -lprocstat

# Static library for pointer checking
STATIC_LIB = libptr_check.a
STATIC_SRC = ptr_check_lib.c
STATIC_OBJ = ptr_check_lib.o

# Shared library for LD_PRELOAD (intercepts write/sendmsg)
SHARED_LIB = libptr_intercept.so
SHARED_SRC = ptr_checker.c

all: $(STATIC_LIB) $(SHARED_LIB)

# Build static library
$(STATIC_OBJ): $(STATIC_SRC) ptr_check_lib.h
	$(CC) $(CFLAGS) -c -o $(STATIC_OBJ) $(STATIC_SRC)

$(STATIC_LIB): $(STATIC_OBJ)
	$(AR) rcs $(STATIC_LIB) $(STATIC_OBJ)

# Build shared library (links against static library)
$(SHARED_LIB): $(SHARED_SRC) $(STATIC_LIB) ptr_check_lib.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(SHARED_LIB) $(SHARED_SRC) $(STATIC_LIB)

clean:
	rm -f $(STATIC_LIB) $(STATIC_OBJ) $(SHARED_LIB)

.PHONY: all clean
