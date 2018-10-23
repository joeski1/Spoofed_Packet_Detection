#ifndef FWALL_PARSER_H
#define FWALL_PARSER_H

#include <unordered_map>
#include <string>
#include <utility>

using namespace std;

// The struct holding TTL information for given IP.
// Count and AverageTTL filled out upon database query.
struct ip_info {
	array<unsigned int, 256> ttls;	// TTLS observed
	int curAverageTTL;	// Average of these new obsereved TTLS
	int count;		// total packets observed 
	int averageTTL;		// average ttl observed for this ip
};

// This is the mappings of ip to observed ttls where 
// array[i] = number of packets observed with ttl = i
// array[256] and array[257] are the total number of
// packets obsvered and the average ttl. 	
typedef unordered_map<unsigned int, struct ip_info> ttl_mappings;

int fastAtoi(const char *str);
ttl_mappings* parse(char* buffer);

#endif
