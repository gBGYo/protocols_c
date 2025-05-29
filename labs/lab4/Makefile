CC = gcc
LDFLAGS = -L../libs
CFLAGS = -Wall -Wextra -I../headers -O2

lab4: main.o log.o
	$(CC) $(LDFLAGS) -o $@ main.o log.o -lcrisp -lstreebog -lmagma -lkdf_tree_gostr3411_2012_256 

lab4_test: test.o log.o
	$(CC) $(LDFLAGS) -o $@ test.o log.o -lcrisp -lstreebog -lmagma -lkdf_tree_gostr3411_2012_256 

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o lab4_test lab4