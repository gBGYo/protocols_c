CC = gcc
LDFLAGS = -L../libs
CFLAGS = -Wall -Wextra -I../headers -O2

lab3: main.o log.o
	$(CC) $(LDFLAGS) -o $@ main.o log.o -lstreebog

lab3_test: test.o log.o
	$(CC) $(LDFLAGS) -o $@ test.o log.o -lstreebog

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o lab3_test lab3 out/prnums