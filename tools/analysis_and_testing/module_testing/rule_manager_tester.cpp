#include <rule_manager.h>
#include <stdio.h>
#include <unistd.h>
#include <sstream>

using namespace std;

void send_packets(string ip, int count) {
	stringstream ss;
	
	ss << "hping3 127.0.0.1 --udp -c " << count << " -i u1000 -a " << ip;
	system(ss.str().c_str());
}

void send_packet(string ip) {
	send_packets(ip, 1);
}

void send_ttl_packet(string ip, int ttl) {
	stringstream ss;

	ss << "hping3 127.0.0.1 --udp -c 1 --ttl " << ttl << " -a " << ip;
	system(ss.str().c_str());
}

void test_rate_limit(RuleManager *rm, string ip) {	
	rm->rate_limit_per_s_ = 5;

	send_packet(ip);	// should accept
	rm->add_limit_rule(ip, 10);

	send_packets(ip, 5);	// 2x accept, 3x deny

	sleep(2);

	send_packet(ip);	// should deny

	sleep(10);

	send_packets(ip, 5);	// 5x accept
}

void test_drop_ttl(RuleManager *rm, string ip) {

	send_packet(ip);		// should accept
	rm->add_drop_rule(ip, 50, 60, 5);

	sleep(1);
	send_ttl_packet(ip, 55);	// should accept
	send_ttl_packet(ip, 45);	// should deny
	send_ttl_packet(ip, 62);	// should deny

	sleep(8);
	send_ttl_packet(ip, 45);	// should accept
}

// Testing timed drop rule. This sends a packet (which should be accepted),
// adds the drop rule to last 5 seconds, sends another packet one second later
// (should be blocked by the rule), then sends another 8 seconds after that 
// (should be accepted as the 5 second rule should have expired)
// Expected output: accept, deny, accept.
void test_drop(RuleManager *rm, string ip) {

	send_packet(ip);	// should accept
	rm->add_drop_rule(ip, 5);

	sleep(1);
	send_packet(ip);	// should deny

	sleep(8);
	send_packet(ip); 	// should accept
}

int main(int argc, char **argv) {
	RuleManager *rm = new RuleManager();
	rm->setup(true);

	// test_drop(rm, "70.70.70.70");
	// test_drop_ttl(rm, "71.71.71.71");
	test_rate_limit(rm, "72.72.72.72");
	delete rm;
}
