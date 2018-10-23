#include <unordered_map>
#include <iostream>
#include <string>
#include <sstream>
#include <unordered_map>
#include "fwall_parser.h"

int fastAtoi(const char *str)
{
    int val = 0;
    while( *str ) {
        val = val*10 + (*str++ - '0');
    }
    return val;
}

// Given a line of ttl values in the form occurance1xttlvalue2 occurance2xttlvalue2
// (e.g. 12x54 14x55 10x64), this function splits the line up and adds them to the mappings
// Params:
// 	ttls		- ttl string 
//	mappings	- ip to ttl unordered map
void parseTTLS(int ip, string ttls, ttl_mappings *mappings) {
	string no_ttl_str, ttl_str;
	int x_pos, count = 0, total = 0, ttl_no, no_ttl_no;
	array<unsigned int, 256> observed_ttls = {0};
	istringstream iss(ttls);

	struct ip_info ipinfo;
	ipinfo.ttls = observed_ttls;
	ipinfo.count = 0;
	ipinfo.averageTTL = 0;

	do {
		string subs;
		iss >> subs;
		if(subs.length() > 2) {
			x_pos = subs.find("x");
			no_ttl_str = subs.substr(0, x_pos);
			ttl_str = subs.substr(x_pos + 1);
			ttl_no = fastAtoi(ttl_str.c_str());
			no_ttl_no = fastAtoi(no_ttl_str.c_str());
			count += no_ttl_no;
			total += no_ttl_no * ttl_no;
			ipinfo.ttls[ttl_no] += no_ttl_no;
		}
	} while(iss);
	
	ipinfo.curAverageTTL = total/count;
	mappings->insert({ip, ipinfo});
}

// Parses an ip log line in the form '[IP]t[tcp_values]u[udp_values]'
// tcp and udp values in the form occurance1xttlvalue2 occurance2xttlvalue2
// (e.g. 12x54 14x55 10x64). Splits the line into IP, and combined observed 
// ttl values for both protocls and stores them in the mappings
void parseLine(string line, ttl_mappings *mappings) {
	string ip, tcps, udps;
	int tcp_pos, udp_pos;
	unsigned int ip_int;
	if(line.length() < 5) return;

	tcp_pos = line.find("t");
	udp_pos = line.find("u");
	ip = line.substr(0, tcp_pos);
	ip_int = fastAtoi(ip.c_str());

	if(udp_pos - tcp_pos > 2) {
		tcps = line.substr(tcp_pos + 2, udp_pos - (tcp_pos + 2));
		parseTTLS(ip_int, tcps, mappings);
	}

	if(line.length() - udp_pos > 2) {
		udps = line.substr(udp_pos + 2);
		parseTTLS(ip_int, udps, mappings);
	}
}

ttl_mappings* parse(char *buffer) {
	ttl_mappings *mappings;
	int count = 0;
	string line;

	mappings = new unordered_map<unsigned int, struct ip_info>;

	istringstream f(buffer);
	while (getline(f, line)) {
		//cout << "LINE: " << line << endl;
		parseLine(line, mappings);
		count++;
	}
	
	cout << "Successfully read " << count << " entries. " << endl;

	return mappings;
}



