# Makefile for ptr_checker FD tests

CC = clang
CFLAGS = -Wall -Wextra -O0 -g -I..
LDFLAGS = -L.. -lmsg_generator

# Parent directory paths
PARENT_DIR = ..
LIB_MSG_GEN = $(PARENT_DIR)/libmsg_generator.a

# Test programs
PROGS = fd_receiver fd_sender_test

.PHONY: all clean test

all: $(PROGS)

# Build the message generator library if needed
$(LIB_MSG_GEN):
	@echo "Building message generator library..."
	$(MAKE) -C $(PARENT_DIR) libmsg_generator.a

# Receiver program (no external dependencies)
fd_receiver: fd_receiver.c
	$(CC) $(CFLAGS) -o $@ $<

# Sender test program (depends on msg_generator library)
fd_sender_test: fd_sender_test.c $(LIB_MSG_GEN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Run the test
test: all
	@echo ""
	@echo "Running FD send/receive test..."
	@echo "================================"
	./fd_sender_test

clean:
	rm -f $(PROGS) *.o core
	rm -f test_output.txt

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build all test programs (default)"
	@echo "  test         - Build and run the FD test"
	@echo "  clean        - Remove built files"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Test programs:"
	@echo "  fd_receiver      - Receives and validates data from FD"
	@echo "  fd_sender_test   - Sends data via FD using msg_generator"
