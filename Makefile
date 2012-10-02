CC	= gcc
CFLAGS	= -O4 -Wall -lcurl
DEST	= /usr/local/bin
SOURCES	= mc_logwatcher.c
PROGRAM	= mc_logwatcher

all: $(PROGRAM)

$(PROGRAM): $(SOURCES)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(SOURCES)
clean:
	rm -f $(PROGRAM)

install: $(PROGRAM)
	install -m 755 -s $(PROGRAM) $(DEST)

uninstall:
	rm -f $(DEST)/$(PROGRAM)
