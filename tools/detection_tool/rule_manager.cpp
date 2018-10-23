#include <stdlib.h>
#include <sstream>
#include <chrono>
#include <thread>
#include <iostream>
#include <iterator>
#include "rule_manager.h"

using namespace std;

// Continuely loops through the timeout mappings and executes
// the ascociated drop rule when the alloted time has passed.
void RuleManager::rule_timeouts(timeout_mappings *mappings) {
	while(true) {
		auto it = mappings->begin();
		while(it != mappings->end()) {
			if(it->second == 0) {
				cout << "EXECING " << it->first.c_str() << endl;
				system(it->first.c_str());
				it = mappings->erase(it);
			} else {
				it->second--;
				it++;
			}
		}
		this_thread::sleep_for(chrono::seconds(1));
	}
}

void RuleManager::add_drop_rule(string ip, unsigned long timeout) {
	stringstream ss, drop_ss;

	ss << "iptables -A " << manager_chain_ << " -s " << ip << " -j " << blocker_chain_ << ";";
	
	system(ss.str().c_str());
	
	drop_ss << "iptables -D " << manager_chain_ << " -s " << ip << " -j " << blocker_chain_ << ";";
	this->timeout_mappings_->insert({drop_ss.str(), timeout});
}

void RuleManager::add_drop_rule(string ip) {
	add_drop_rule(ip, default_timeout_s_);
}

void RuleManager::add_drop_rule(string ip, int ttl_lower, int ttl_higher, unsigned long timeout) {
	stringstream ss, drop_ss;

	ss << "iptables -A " << manager_chain_ << " -m ttl --ttl-gt " << ttl_higher \
		<< " -j " << blocker_chain_ \
		<< "; iptables -A " << manager_chain_ << " -m ttl --ttl-lt " << ttl_lower \
		<< " -j " << blocker_chain_ << ";";

	system(ss.str().c_str());

	drop_ss << "iptables -D " << manager_chain_ << " -m ttl --ttl-gt " << ttl_higher \
		<< " -j " << blocker_chain_ \
		<< "; iptables -D " << manager_chain_ << " -m ttl --ttl-lt " << ttl_lower \
		<< " -j " << blocker_chain_ << ";";

	this->timeout_mappings_->insert({drop_ss.str(), timeout});
} 

void RuleManager::add_drop_rule(string ip, int ttl_lower, int ttl_higher) {
	add_drop_rule(ip, ttl_lower, ttl_higher, default_timeout_s_);
}

void RuleManager::add_limit_rule(string ip, unsigned long timeout) {
	stringstream ss, drop_ss;

	ss << "iptables -A " << this->manager_chain_ << " -s " << ip \
		<< " -j " << this->rate_limit_chain_ << ";";

	system(ss.str().c_str());

	drop_ss << "iptables -D " << this->manager_chain_ << " -s " << ip \
		<< " -j " << this->rate_limit_chain_ << ";";

	this->timeout_mappings_->insert({drop_ss.str(), timeout});
	
}

void RuleManager::add_limit_rule(string ip) {
	add_limit_rule(ip, default_timeout_s_);
}

void RuleManager::setup(bool flush) {
	stringstream ss;

	this->timeout_mappings_ = new unordered_map<string, unsigned long>;
	
	ss << "iptables -N " << this->manager_chain_ << ";";
	ss << "iptables -N " << this->blocker_chain_ << ";";
	ss << "iptables -N " << this->rate_limit_chain_ << ";";

	if(flush) {
		ss << "iptables -F " << this->manager_chain_ << ";";
	}
	ss << "iptables -F " << this->blocker_chain_ << ";";
	ss << "iptables -F " << this->rate_limit_chain_ << ";";

	if(this->log_dropped_packets) {
		ss << "iptables -A " << this->blocker_chain_ << " -j LOG --log-prefix \"Dropping packet: \";";
	}
	if(!(this->monitor_mode)) ss << "iptables -A " << this->blocker_chain_ << " -j DROP;";
	ss << "iptables -A " << this->rate_limit_chain_ << "\
		    --match hashlimit \
		    --hashlimit-mode srcip \
		    --hashlimit-upto "<< rate_limit_per_s_ << "/sec \
		    --hashlimit-burst 20 \
		    --hashlimit-name conn_rate_limit \
		    -j ACCEPT;";
	ss << "iptables -D " << this->appending_chain_ << " -j " << this->manager_chain_ << ";";
	ss << "iptables -A " << this->appending_chain_ << " -j " << this->manager_chain_ << ";";

	system(ss.str().c_str());
	thread t(rule_timeouts, this->timeout_mappings_);
	t.detach();
}
