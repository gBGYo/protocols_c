CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -I./src -O2
CXXFLAGS = $(CFLAGS)
LDFLAGS = -L./lib
LDLIBS = -lmagma

# Test configuration
TEST_SRCS = tests/test_magma.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)
TEST_EXE = test_magma
GTEST_LIBS = -lgtest -lgtest_main -lpthread

# Library source files
LIB_SRCS = src/magma.c
LIB_OBJS = $(LIB_SRCS:.c=.o)
LIB_NAME = libmagma.a

# Main program
MAIN_SRC = main.c
MAIN_OBJ = $(MAIN_SRC:.c=.o)
MAIN_EXE = magma

.PHONY: all clean test

all: $(MAIN_EXE)

# Build the static library
$(LIB_NAME): $(LIB_OBJS)
	ar rcs lib/$(LIB_NAME) $(LIB_OBJS)

# Build the main program
$(MAIN_EXE): $(MAIN_OBJ) $(LIB_NAME)
	$(CC) $(LDFLAGS) -o $@ $(MAIN_OBJ) $(LDLIBS)

# Build and run tests
test: $(TEST_EXE)
	./$(TEST_EXE)

$(TEST_EXE): $(TEST_OBJS) $(LIB_NAME)
	$(CXX) $(LDFLAGS) -o $@ $(TEST_OBJS) $(LDLIBS) $(GTEST_LIBS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

rand:
	# dd if=/dev/urandom of=test_files/in/1M bs=1M count=1
	# dd if=/dev/urandom of=test_files/in/100M bs=100M count=1
	# dd if=/dev/urandom of=test_files/in/1000M bs=1000M count=1
	hyperfine "/home/gbgyo/protocols_c/magma/magma test_files/in/1M test_files/out/1M"
	hyperfine "/home/gbgyo/protocols_c/magma/magma test_files/in/100M test_files/out/100M" 
	hyperfine "/home/gbgyo/protocols_c/magma/magma test_files/in/1000M test_files/out/1000M"

clean:
	rm -f $(LIB_OBJS) $(MAIN_OBJ) $(MAIN_EXE) lib/$(LIB_NAME) $(TEST_OBJS) $(TEST_EXE) 
