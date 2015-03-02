OBJS = synfrag.o checksums.o flag_names.o packets.o
SRCS = $(OBJS,.o=.c)
# For some reason, clang corrupts the constant strings returned in flag_names.
# It was my understanding they're static and safe to return as const char *
# so either I'm wrong or it's a compiler bug. Either way, -Os fixes it.
CFLAGS += -Wall -O0
LDFLAGS += -lpcap
PROGNAME = synfrag

all: $(PROGNAME)

$(PROGNAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROGNAME) $(OBJS)

clean:
	rm -rf $(OBJS) $(PROGNAME)

