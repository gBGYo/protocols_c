CC = gcc
LDFLAGS = -L../libs
CFLAGS = -Wall -Wextra -I../headers -O2

lab1: main.o log.o
	$(CC) $(LDFLAGS) -o $@ main.o log.o -lkuznyechik -lkdf_tree_gostr3411_2012_256 -lstreebog

lab1_test: test.o log.o
	$(CC) $(LDFLAGS) -o $@ test.o log.o -lkuznyechik -lkdf_tree_gostr3411_2012_256 -lstreebog

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o lab1_test lab1 dec/* out/*