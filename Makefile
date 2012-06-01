OBJS = synfrag.o checksums.o flag_names.o packets.o
SRCS = $(OBJS,.o=.c)
CFLAGS += -Wall

all: synfrag

synfrag: $(OBJS)
	$(CC) $(LDFLAGS) -lpcap -o synfrag $(OBJS)

clean:
	rm -rf $(OBJS) synfrag

