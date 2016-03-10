VERSION = 0.1
CC      = gcc
CFLAGS  = -O2 -DVERSION=\"$(VERSION)\"
OUT     = rfc2047_dec

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)

# default target
all:	$(OBJ)
	$(CC) $(CFLAGS) -o $(OUT) $(LDFLAGS) $(OBJ)

# debug target
debug:	CFLAGS += -O0 -g -DDEBUG
debug:	$(OBJ)
	$(CC) $(CFLAGS) -o $(OUT) $(LDFLAGS) $(OBJ)

clean:
	rm -rf *.o $(OUT)

