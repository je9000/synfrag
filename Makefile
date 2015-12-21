OBJS = synfrag.o checksums.o flag_names.o packets.o
SRCS = $(OBJS,.o=.c)
CFLAGS += -Wall -fno-strict-aliasing
LDFLAGS += -lpcap
PROGNAME = synfrag

all: $(PROGNAME)

$(PROGNAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROGNAME) $(OBJS)

clean:
	rm -rf $(OBJS) $(PROGNAME)

