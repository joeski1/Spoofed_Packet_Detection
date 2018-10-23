.PHONY: all clean

CC = g++

###################################

SOURCE = $(wildcard *.cpp) #
HEADER = $(SOURCE:.c=.h)
OBJS = $(SOURCE:.c=.o)
TARGET = $(SOURCE:.cpp=)


###################################

#standard rules
all:  fwall_reader

fwall_reader: fwall_reader.cpp ttl_pinger.c rule_manager.cpp spoof_detector.cpp psql_ops.cpp
	$(CC) -I /usr/local/include/boost_1_66_0 -Wall -std=c++0x -pthread spoof_detector.cpp fwall_reader.cpp fwall_parser.cpp sqlite_ops.cpp ttl_pinger.c rule_manager.cpp psql_ops.cpp -lpqxx -lpq -o fwall_reader -l sqlite3

clean:
	rm -f $(OBJS) $(TARGET)

###################################


#EOF
