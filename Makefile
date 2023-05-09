LDLIBS += -lnetfilter_queue

all: 1m-block

1m-block: 1m-block.c

clean:
	rm -f 1m-block *.o
