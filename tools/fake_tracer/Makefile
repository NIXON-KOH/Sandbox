CC = gcc
CFLAGS = -fPIC -Wall -O2 -shared
TARGET = libfake_tracer.so

all: $(TARGET)

$(TARGET): fake_tracer.c
	$(CC) $(CFLAGS) -o $(TARGET) fake_tracer.c -ldl

clean:
	rm -f $(TARGET)