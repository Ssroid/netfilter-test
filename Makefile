CC=gcc
TARGET=nfqnl_test
SRC=nfqnl_test.c
LDFLAGS=-lnetfilter_queue

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
	rm -f *.o


