CC = cc
CFLAGS = -fPIC -Wall -Wextra -O0 -g
LDFLAGS = -shared -lprocstat

TARGET = libptr_checker.so
SRC = ptr_checker.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
