CC = clang

# Configuration Options
# Set to 1 to enable, 0 to disable. Override on command line: make OPTION=0

# DEBUG: Enable debug output and verbose logging
DEBUG = 0

################### Sould we check only MSAN? PTR? or both? ###################

# ENABLE_PTR_CHECK: Enable pointer leak detection
# Scans buffers for values that fall within process virtual memory regions
ENABLE_PTR_CHECK = 1

# ENABLE_MSAN_CHECK: Enable MemorySanitizer checks for uninitialized memory
# Requires linking with -fsanitize=memory for full functionality
ENABLE_MSAN_CHECK = 1


################### what function should we intercept? ###################

# add more functions to here if you adds more later

# INTERCEPT_SENDMSG: Intercept sendmsg() system call
# Checks all iovec buffers before transmission
INTERCEPT_SENDMSG = 1

# INTERCEPT_IMSG_COMPOSE: Intercept imsg_compose() function
# Checks message data buffer before composing imsg
INTERCEPT_IMSG_COMPOSE = 0

# INTERCEPT_IMSG_COMPOSEV: Intercept imsg_composev() function
# Checks all iovec buffers before composing imsg
INTERCEPT_IMSG_COMPOSEV = 0

# INTERCEPT_MUST_WRITE: Intercept must_write() function
# Checks buffer before writing
INTERCEPT_MUST_WRITE = 0

# INTERCEPT_WRITE: Intercept write() system call
# Checks buffer before writing
INTERCEPT_WRITE = 0

######################################

CFLAGS = -fPIC -Wall -Wextra -O0 -g
.if ${DEBUG} == 1
CFLAGS += -DDEBUG_BUFFER_CHECK
CFLAGS += -fsanitize-recover=memory # important!

.endif
.if ${ENABLE_PTR_CHECK} == 1
CFLAGS += -DENABLE_PTR_CHECK
.endif
.if ${ENABLE_MSAN_CHECK} == 1
CFLAGS += -DENABLE_MSAN_CHECK
.endif
.if ${INTERCEPT_SENDMSG} == 1
CFLAGS += -DINTERCEPT_SENDMSG
.endif
.if ${INTERCEPT_IMSG_COMPOSE} == 1
CFLAGS += -DINTERCEPT_IMSG_COMPOSE
.endif
.if ${INTERCEPT_IMSG_COMPOSEV} == 1
CFLAGS += -DINTERCEPT_IMSG_COMPOSEV
.endif
.if ${INTERCEPT_MUST_WRITE} == 1
CFLAGS += -DINTERCEPT_MUST_WRITE
.endif
.if ${INTERCEPT_WRITE} == 1
CFLAGS += -DINTERCEPT_WRITE
.endif
LDFLAGS = -shared -lprocstat -lmd

# Object files
BUFFER_CHECK_OBJ = buffer_check_lib.o
BUFFER_INTERCEPT_OBJ = buffer_checker.o
EOM_COUNTER_OBJ = eom_counter.o

# Combined shared library (both buffer checking and LD_PRELOAD interception)
COMBINED_LIB = libbuffer_check.so

# Separate EOM counter library
EOM_COUNTER_LIB = libeom_counter.so

all: $(COMBINED_LIB) $(EOM_COUNTER_LIB)

# Build object files
$(BUFFER_CHECK_OBJ): buffer_check_lib.c buffer_check_lib.h
	$(CC) $(CFLAGS) -c -o $(BUFFER_CHECK_OBJ) buffer_check_lib.c

$(BUFFER_INTERCEPT_OBJ): buffer_checker.c buffer_check_lib.h
	$(CC) $(CFLAGS) -c -o $(BUFFER_INTERCEPT_OBJ) buffer_checker.c

$(EOM_COUNTER_OBJ): eom_counter.c eom_counter.h
	$(CC) $(CFLAGS) -c -o $(EOM_COUNTER_OBJ) eom_counter.c

# Build combined shared library (contains buffer_check, interception, and eom_counter)
$(COMBINED_LIB): $(BUFFER_CHECK_OBJ) $(BUFFER_INTERCEPT_OBJ) $(EOM_COUNTER_OBJ)
	$(CC) $(CFLAGS) -shared -o $(COMBINED_LIB) $(BUFFER_CHECK_OBJ) $(BUFFER_INTERCEPT_OBJ) $(EOM_COUNTER_OBJ) -lprocstat -lmd

# Build separate EOM counter shared library
$(EOM_COUNTER_LIB): $(EOM_COUNTER_OBJ)
	$(CC) $(CFLAGS) -shared -o $(EOM_COUNTER_LIB) $(EOM_COUNTER_OBJ)

clean:
	rm -f $(COMBINED_LIB) $(EOM_COUNTER_LIB) $(BUFFER_CHECK_OBJ) $(BUFFER_INTERCEPT_OBJ) $(EOM_COUNTER_OBJ)

.PHONY: all clean
