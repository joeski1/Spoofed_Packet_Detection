#ifndef SPOOF_DETECTOR_H
#define SPOOF_DETECTOR_H

#include "fwall_parser.h"
#include "rule_manager.h"
#include <mutex>

#define MODE_PASSIVE 1
#define MODE_ACTIVE 2

class SpoofDetector {
	public:
	RuleManager *rm;
	std::mutex iptable_mutex;
	std::mutex sus_mutex;
	bool first_occ_policy = POLICY_ACCEPT;
	int mode = MODE_ACTIVE;
	int suspicious_per_sec_threshold = -1;	// When this threshold is passed, the mode switches to MODE_ACTIVE
	int suspicious_per_sec = 0;

	// static void first_occurance(unsigned int id, const pair<unsigned int, struct ip_info> & cref_element);
	bool is_suspicious(unsigned int ip, struct ip_info ipinfo);	// Returns true if the ip is suspicious given
									// the information held in ipinfo
	bool handle(unsigned int ip, struct ip_info ipinfo);		// Returns true if action was taken
	void deal_with_first_occurances(ttl_mappings *mappings);
	void setup();
	void set_first_occ_policy(int policy);
	void set_monitor_mode(bool mode);
};

#endif
