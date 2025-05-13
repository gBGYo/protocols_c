CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -I./src -I../chacha20/src -I../kdf_tree_gostr3411_2012_256/src -I../magma/src -I../streebog/src -O0
CXXFLAGS = $(CFLAGS)
LDFLAGS = -L./lib
LDLIBS = -lcrisp -lchacha20 -lkdf_tree_gostr3411_2012_256 -lmagma -lstreebog


# Test configuration
TEST_SRCS = tests/test_crisp.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)
TEST_EXE = test_crisp
GTEST_LIBS = -lgtest -lgtest_main -lpthread

# Library source files
LIB_SRCS = src/crisp.c
LIB_OBJS = $(LIB_SRCS:.c=.o)
LIB_NAME = libcrisp.a

# Main program
MAIN_SRC = main.c
MAIN_OBJ = $(MAIN_SRC:.c=.o)
MAIN_EXE = crisp

.PHONY: all clean test

all: $(MAIN_EXE)

# Build the static library
$(LIB_NAME): $(LIB_OBJS)
	ar rcs lib/$(LIB_NAME) $(LIB_OBJS)

# Build the main program
$(MAIN_EXE): $(MAIN_OBJ) $(LIB_NAME)
	$(CC) $(LDFLAGS) -o $@ $(MAIN_OBJ) $(LDLIBS) -ggdb

# Build and run tests
test: $(TEST_EXE)
	./$(TEST_EXE)

$(TEST_EXE): $(TEST_OBJS) $(LIB_NAME)
	$(CXX) $(LDFLAGS) -o $@ $(TEST_OBJS) $(LDLIBS) $(GTEST_LIBS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -ggdb

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(LIB_OBJS) $(MAIN_OBJ) $(MAIN_EXE) lib/$(LIB_NAME) $(TEST_OBJS) $(TEST_EXE) 