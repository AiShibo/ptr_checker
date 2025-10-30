CC = clang
DEBUG = 1
CFLAGS = -fPIC -Wall -Wextra -O0 -g
.if ${DEBUG} == 1
CFLAGS += -DDEBUG_PTR_CHECK
.endif
LDFLAGS = -shared -lprocstat -lmd

# Object files
PTR_CHECK_OBJ = ptr_check_lib.o
PTR_INTERCEPT_OBJ = ptr_checker.o

# Combined shared library (both ptr checking and LD_PRELOAD interception)
COMBINED_LIB = libptr_check.so

all: $(COMBINED_LIB)

# Build object files
$(PTR_CHECK_OBJ): ptr_check_lib.c ptr_check_lib.h
	$(CC) $(CFLAGS) -c -o $(PTR_CHECK_OBJ) ptr_check_lib.c

$(PTR_INTERCEPT_OBJ): ptr_checker.c ptr_check_lib.h
	$(CC) $(CFLAGS) -c -o $(PTR_INTERCEPT_OBJ) ptr_checker.c

# Build combined shared library (contains both ptr_check functions and interception)
$(COMBINED_LIB): $(PTR_CHECK_OBJ) $(PTR_INTERCEPT_OBJ)
	$(CC) $(CFLAGS) -shared -o $(COMBINED_LIB) $(PTR_CHECK_OBJ) $(PTR_INTERCEPT_OBJ) -lprocstat -lmd

clean:
	rm -f $(COMBINED_LIB) $(PTR_CHECK_OBJ) $(PTR_INTERCEPT_OBJ)

.PHONY: all clean
