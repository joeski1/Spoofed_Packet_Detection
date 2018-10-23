#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include <unordered_map>
#include <string>
#include <utility>

#define POLICY_ACCEPT 1
#define POLICY_DROP 2
#define POLICY_PING 3

typedef std::unordered_map<std::string, unsigned long> timeout_mappings;

// This class utilises the program iptables to drop and limit connections from
// a given ip address. 
class RuleManager {

	public:
	std::string appending_chain_ = "INPUT"; // Where to append the chains from
	std::string manager_chain_ = "TTL_MANAGER"; // Name of main chain
	std::string blocker_chain_ = "TTL_DROP_AND_LOG"; // Name of main chain
	std::string rate_limit_chain_ = "TTL_RATE_LIMIT"; // Name of rate limit chain
	unsigned int rate_limit_per_s_ = 50; // How many connections a second a rate limited IP can make
	unsigned long default_timeout_s_ = 3600; // How long a rule exists for in seconds (default one hour)
	bool log_dropped_packets = true;
	int first_occ_policy = POLICY_ACCEPT;
	bool monitor_mode = false; // Logs packets instead of dropping them

	// Passed a boolean value to flush all existing rules. 
	// By default the rules are flushed.
	void setup(bool flush);

	// Functions for adding rules to drop or limit packets from a given source IP. 
	// Can restrict packets within a given ttl range.	
	void add_drop_rule(std::string ip);
	void add_drop_rule(std::string ip, unsigned long timeout);
	void add_drop_rule(std::string ip, int ttl_lower, int ttl_higher);
	void add_drop_rule(std::string ip, int ttl_lower, int ttl_higher, unsigned long timeout); 

	void add_limit_rule(std::string ip);
	void add_limit_rule(std::string ip, unsigned long timeout);

	private:
	timeout_mappings *timeout_mappings_; // Unordered map of the drop rule and a time of when to execute them
	// Function for handling timouts for rules
	static void rule_timeouts(timeout_mappings *);
		
};

#endif
