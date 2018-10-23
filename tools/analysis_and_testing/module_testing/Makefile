.PHONY: all clean

CC = g++

###################################

SOURCE = $(wildcard *.cpp) #
HEADER = $(SOURCE:.c=.h)
OBJS = $(SOURCE:.c=.o)
TARGET = $(SOURCE:.cpp=)

INC=-I/home/joe/final_year_project_masters/data_collection/reading/advanced_readers
# INC_PARAMS=$(foreach d, $(INC), -I$d)


###################################

#standard rules
all:  ping rule

ping: ttl_ping_test.c
	gcc $(INC) -Wall ../../detection_tool/ttl_pinger.c ttl_ping_test.c -o ttl_ping_test

rule: rule_manager_tester.cpp
	$(CC) $(INC) -Wall -std=c++0x -pthread ../../detection_tool/rule_manager.cpp rule_manager_tester.cpp -o rule_manager_tester

clean:
	rm -f $(OBJS) $(TARGET)

###################################


#EOF
