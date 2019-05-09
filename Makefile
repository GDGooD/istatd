CC=gcc
CCFLAGS = -O3
DEPS = btree.h btree.c
LIBS = -lpcap
IPATH = /usr/local/bin/

all: istat istatd

istat:
	$(CC) $(CCFLAGS) $(DEPS) -o istat istat.c

istatd:
	$(CC) $(CCFLAGS) $(DEPS) -o istatd istatd.c $(LIBS)

install: all
	cp ./istat $(IPATH)istat
	cp ./istatd $(IPATH)istatd

purge: remove
	rm -rf /etc/istatd/
  
remove:
	rm $(IPATH)istat
	rm $(IPATH)istatd

clean:
	rm -f ./istat
	rm -f ./istatd


