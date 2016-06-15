# Makefile for co_sched tool

CC = $(CROSS_COMPILE)gcc
DEFINES=

CFLAGS = -O2 -Wall

all: co_sched
%: %.c %.S
	$(CC) $(DEFINES) $(CFLAGS) -o $@ $^

clean:
	$(RM) co_sched *~
