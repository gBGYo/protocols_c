CC = gcc
LDFLAGS = -L../libs
CFLAGS = -Wall -Wextra -I../headers -O2

lab2: main.o log.o
	$(CC) $(LDFLAGS) -o $@ main.o log.o -lkdf_tree_gostr3411_2012_256 -lstreebog 

lab2_test: test.o log.o
	$(CC) $(LDFLAGS) -o $@ test.o log.o -lkdf_tree_gostr3411_2012_256 -lstreebog 

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o lab2_test lab2 key_new