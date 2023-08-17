CC = gcc
CFLAGS = -g -Wall
SOURCES = $(wildcard *.c)
BUILDDIR = build/
OBJS = $(patsubst %.c, $(BUILDDIR)%.o, $(SOURCES))
BINARY = dns_resolver

all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILDDIR)%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR):
	mkdir -p $@

clean:
	rm $(BINARY) $(OBJS)

.PHONY: all clean
