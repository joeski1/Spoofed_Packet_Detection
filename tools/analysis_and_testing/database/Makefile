.PHONY: all clean

CC = g++

###################################

SOURCE = $(wildcard *.cpp)
HEADER = $(SOURCE:.c=.h)
OBJS = $(SOURCE:.c=.o)
TARGET = $(SOURCE:.cpp=)


###################################

#standard rules
all:  database_analysis

database_analysis: database_analysis.cpp
	$(CC) -Wall -std=c++0x database_analysis.cpp -o database_analysis -l sqlite3

clean:
	rm -f $(OBJS) $(TARGET)

###################################


#EOF
