#include <unordered_map>
#include <iostream>
#include <fstream>
#include "spoof_detector.h"
#include "fwall_parser.h"
#include "ttl_pinger.h"
#include "ctpl.h"

using namespace std;

#define NIPQUAD(addr) \
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

string time_stamp() {
	const auto now = time(nullptr) ;
	char cstr[256] {};
	return strftime( cstr, sizeof(cstr), "%d-%m %H:%M:%S: ", localtime(&now) ) ? cstr : "" ;
}

// Maintains the 'suspicious_per_sec' integer. If this number
// exceeds suspciious_per_sec_threshold
static void suspcious_per_sec_manager(SpoofDetector *sd) {
	while(true) {
		if(sd->suspicious_per_sec > sd->suspicious_per_sec_threshold) {
			sd->mode = MODE_ACTIVE;
		} else {
			sd->mode = MODE_PASSIVE;
		}
		if(sd->suspicious_per_sec > 0) sd->suspicious_per_sec--;
		this_thread::sleep_for(chrono::seconds(1));
	}
}

// Checks for a ttl change, logs the new change and makes the new
// average the 'true' average. This is for monitoring purposes to
// see how often routes change through the internet. Assumes all
// packets are not spoofed.
void checkChange(unsigned int ip, struct ip_info ipinfo) {
	if(ipinfo.curAverageTTL != 0 && abs(ipinfo.averageTTL - ipinfo.curAverageTTL) > 2) {
		ofstream myfile;
  		myfile.open("ttl_change_log.txt", ios::app);
  		myfile << time_stamp() << ip << ": old average ttl: " << ipinfo.averageTTL << \
		" new average ttl: " << ipinfo.curAverageTTL << endl;
	  	myfile.close();
		ipinfo.averageTTL = ipinfo.curAverageTTL;
	}

}

// Returns the estimated hop count the packet took to
// arrive. This presumes all protocols use a starting ttl
// value of either 64, 128 or 255 (which all known ones do)
int ttl_to_hop_count(int ttl) {
	if(ttl <= 64)
		return 64 - ttl;
	else if(ttl <= 128)
		return 128 - ttl;
	else if(ttl <= 255)
		return 255 - ttl;
	else return 0;
}

// This function returns true if the ip address
// is from a private network.
bool is_local(unsigned int ip) {
	char *first_chr, *second_chr;
	unsigned int first, second;

	first_chr = (char *)malloc(sizeof(char)*3);
	second_chr = (char *)malloc(sizeof(char)*3);
	sprintf(first_chr, "%u", ((unsigned char *)&ip)[0]);
	sprintf(second_chr, "%u", ((unsigned char *)&ip)[1]);

	first = fastAtoi(first_chr);
	second = fastAtoi(second_chr);

	switch(first) {
		case 0 	: return true;
		case 10	: return true;
		case 100: if(second == 64)	return true;
		case 127: return true;
		case 172: if(second == 16)	return true;
		case 192: if(second == 168)	return true;
		case 198: if(second == 18)	return true;
	}

	return false;
}

// Returns true if the ip is suspicious given the information held in ipinfo.
// Currently very naive and checks if the hopcounts are different.
bool SpoofDetector::is_suspicious(unsigned int ip, struct ip_info ipinfo) {
	int hop1, hop2, diff;

	if(is_local(ip))
		return false;

	hop1 = ttl_to_hop_count(ipinfo.curAverageTTL);
	hop2 = ttl_to_hop_count(ipinfo.averageTTL);
	diff = hop1 > hop2 ? hop1 - hop2 : hop2 - hop1;

	if(diff > 0) {
		return true;
	}
	return false;
}

// Pings the given IP address and stores ttl as 'true' ttl.
// If the true ttl is suspicious or if the ping failed (for
// example, it was unreachable), a rule is sent to block it.
static void ping_first_occurance(int id, const pair<unsigned int, struct ip_info> & cref_element, const SpoofDetector *cref_sd) {
	int ttl;
	char *ip_chr;
	SpoofDetector *sd = const_cast<SpoofDetector*>(cref_sd);
	pair<unsigned int, struct ip_info> element = const_cast<pair<unsigned int, struct ip_info>&>(cref_element);

	if(is_local(element.first)) return;

	ip_chr = (char*) malloc(20*sizeof(char));
	sprintf(ip_chr, "%u.%u.%u.%u", NIPQUAD(element.first));
	// 	cout << "Pinging " << ip_chr << " (" << element.first << ") to find true ttl.." << endl;
	if(sd->rm->first_occ_policy == POLICY_DROP) {
		sd->rm->add_drop_rule(ip_chr);
	} else if (sd->rm->first_occ_policy == POLICY_PING) {

		ttl = ttl_ping(ip_chr);
		string ip_str(ip_chr);

		if(ttl == -1) {
			cout << "TTL check failed, sending rule to block IP" << ip_chr << endl;
			sd->rm->add_drop_rule(ip_chr);
		} else if(ttl == 0) {
			return;
		}
		element.second.averageTTL = ttl;
		sd->handle(element.first, element.second);
	}

	free(ip_chr);
}

void SpoofDetector::deal_with_first_occurances(ttl_mappings *mappings) {
	ctpl::thread_pool p(8);
	for (pair<unsigned int, struct ip_info> element : *mappings) {
		// cout << "hello " << element.first << ". Count: " << element.second.count << endl;
		if(element.second.count == 0) {
			const pair<unsigned int, struct ip_info> cref_element = element;
			const SpoofDetector *cref_sd = this;
			p.push(ping_first_occurance, cref_element, cref_sd);
		}
	}
}

// Takes an ip and the ascociated ip_info struct and takes action
// according to whether or not the IP packet is spoofed or not
bool SpoofDetector::handle(unsigned int ip, struct ip_info ipinfo) {
	bool action_taken = false;
	char *ip_chrs;
	string ip_str;

	ip_chrs = (char *)malloc(sizeof(char)*17);
	sprintf(ip_chrs, "%u.%u.%u.%u", NIPQUAD(ip));
	ip_str = ip_chrs;

	if(this->is_suspicious(ip, ipinfo)) {
		 cout << "Suspicious ip " << ip_chrs << " - " << ip << ". Had TTL of " \
		 << ipinfo.curAverageTTL << " (expected around " << ipinfo.averageTTL << ")" << endl;
		if(this->mode == MODE_PASSIVE) {
			lock_guard<mutex> guard(sus_mutex);
			this->suspicious_per_sec++;
		} else if(this->mode == MODE_ACTIVE) {
			lock_guard<mutex> guard(iptable_mutex);
			this->rm->add_drop_rule(ip_str, 10);
		}
	}

	free(ip_chrs);
	return action_taken;
}

void SpoofDetector::set_first_occ_policy(int policy) {
	this->rm->first_occ_policy = policy;
}

void SpoofDetector::set_monitor_mode(bool mode) {
	this->rm->monitor_mode = mode;
}

void SpoofDetector::setup() {
	this->rm = new RuleManager();
	rm->setup(true);

	thread t(suspcious_per_sec_manager, this);
	t.detach();
}
