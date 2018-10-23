#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <thread>
#include <sstream>
#include <iostream>
#include <fstream>
#include <ctime>
#include "sqlite_ops.h"
#include "fwall_parser.h"
#include "spoof_detector.h"
#include "rule_manager.h"
#include "psql_ops.h"

using namespace std;

#define NIPQUAD(addr) \
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

/*
	Many untested efficiency decisions. E.G is it better to bulk INSERT OR IGNORE
	everthing, or sort in c++ do which ones should be inserted.

	Cannot multithread with many worker threads as the limiting time factor is speed
	of inserts/updates - can only have one open db conenction at a time.
*/

bool monitor_mode = false;
bool psql_mode = false;
bool collection_mode = false;
SpoofDetector *spoof_detector;
string proc_path = "/proc/firewall_logger";
struct psql_db_info pinfo;

// Opens up the file in /proc and reads from it. Returns the
// contents in a buffer.
char* readFirewallModule() {
	string line;
	char *buffer;
	int len = 0, n = 0;
	int fd;

	fd = open(proc_path.c_str(), O_RDONLY);
	if(fd < 0) {
		printf("ERROR: cannot open /proc/firewall_logger\n");
		return NULL;
	}

	do {
		len = n+10;
 		buffer = (char*) malloc((len+1)*sizeof(char));
		if(buffer == NULL){
			printf("ERROR: malloc failed\n");
			return NULL;
		}
		n = read(fd, buffer, len);
		if(n < 0){
			printf("ERROR: reading\n");
			close(fd);
			return NULL;
		}

	} while (n > len);

	buffer[n] = '\0';
	// cout << buffer << endl;
	close(fd);
	return buffer;
}

void printMappings(ttl_mappings *mappings){
	stringstream ss;

	for (pair<unsigned int, struct ip_info> element : *mappings) {
		ss << element.first << ": ";
		for (int i = 0; i < 256; i++) {
			if(element.second.ttls[i] > 0)
				ss << element.second.ttls[i] << "x" << i << " ";
		}
		ss << "\n";
	}
		cout << ss.str() << endl;
}

// Callback for the sql select query. Updates the average TTL and count
// into the relevant ip_info struct and then calls the spoof_detector
// function handle().
static int selectCallback(void *vmappings, int argc,		// Number of columns in row
					 char **argv,		// An array of strings representing fields in the row
					 char **azColName) { 	// An array of strings representing column names
	ttl_mappings *mappings = static_cast<ttl_mappings *>(vmappings);
	unsigned int ip = fastAtoi(argv[0]);
	struct ip_info *ipinfo = &(*mappings)[ip];

	ipinfo->averageTTL = fastAtoi(argv[1]);
	ipinfo->count = fastAtoi(argv[2]);

	// printf("ipinfo current count: %d\n", ipinfo->count);
	if(!collection_mode) {
		if(spoof_detector->handle(ip, *ipinfo)) {
			mappings->erase(ip);
		}
	}
	return 0;
}

/* Main control flow of the program.
	1) Grab all data from /proc/
	2) Sort data into a mapping of ip to ip_info struct (includes observed ttls)
	3) Grab averages + number of inserts per source ip
		- Check for questionabl ttls  and deal accordingly (using avgs + n.o inserts)
	4) Insert inserts
	5) Update updates with new averages
*/
void parseTask() {
	sqlite3 *db;
	int rc;
	stringstream ss;
	char *buffer;
	ttl_mappings *mappings;

	if((buffer = readFirewallModule()) == NULL) {
		fprintf(stderr, "Error reading proc\n");
		return;
	}

	mappings = parse(buffer);
	// printMappings(mappings);

	rc = sqlite3_open("ipdb.db", &db);

	if(rc) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return;
	}

	selectAveragesAndCount(db, mappings, selectCallback);

	if(!collection_mode) spoof_detector->deal_with_first_occurances(mappings);


	insertTTLS(db, mappings);
	updateTTLS(db, mappings);

	if(psql_mode) update_psql_db(mappings, pinfo);

	delete mappings;
	sqlite3_close(db);
}

int read_psql_confs() {
	stringstream is_file;
	ifstream file( "psql.conf" );
	if(file) {
        	is_file << file.rdbuf();
        	file.close();
	} else {
		return 1;
	}

	string line;
	while(getline(is_file, line) )
	{
	  istringstream is_line(line);
	  string key;
	  if(getline(is_line, key, '=') )
	  {
	    string value;
	    if(getline(is_line, value) ) {
		if(!key.compare("schema")) {
			pinfo.schema = value;
		} else if(!key.compare("table")) {
			pinfo.table = value;
		} else if(!key.compare("dbname")) {
			pinfo.dbname = value;
		} else if(!key.compare("user")) {
			pinfo.user = value;
		} else if(!key.compare("password")) {
			pinfo.password = value;
		} else if(!key.compare("hostaddr")) {
			pinfo.hostaddr = value;
		} else {
			cout << "unknown configuration " << key << endl;
		}
	    }
	  }
	}

	if(pinfo.schema.empty()) {
		cout << "Configuration schema not found." << endl;
		return 1;
	} else if(pinfo.table.empty()) {
		cout << "Configuration table not found." << endl;
		return 1;
	} else if(pinfo.dbname.empty()) {
		cout << "Configuration dbname not found." << endl;
		return 1;
	} else if(pinfo.user.empty()) {
		cout << "Configuration user not found." << endl;
		return 1;
	} else if(pinfo.password.empty()) {
		cout << "Configuration password not found." << endl;
		return 1;
	} else if(pinfo.hostaddr.empty()) {
		cout << "Configuration hostaddr not found." << endl;
		return 1;
	}
	return 0;
}

void print_help(){

	cout << "Usage: ./fwall_reader \n" << \
		"	-D	data collection mode - does not take action on suspicious packets\n "<< \
		"	-E	empties the kernel data structure but doesn't store the data\n "<< \
		"	-M	monitoring mode - logs TTL changes rather than dropping\n "<< \
		"	-P	uploads information to the psql database\n "<< \
		"	-p	[drop, accept, ping] policy for dealing with first occurance of IP addresses. (default accept)\n "<< \
		"	-R	cleans the database\n " << \
		"       -t	time in seconds in between reads\n " << endl;
}

int main (int argc, char** argv) {
	size_t sleep_time = 0;
	bool empty = false, reset = false;
	long double t;
	int ch, first_occ_policy = POLICY_ACCEPT;

	while ((ch = getopt(argc, argv, "EhMPp:Rt:")) != EOF) {
		switch(ch) {
			case 'D':
				collection_mode = true;
				break;
			case 'E':
				empty = true;
				break;
			case 'h':
				print_help();
				return 0;
			case 'M':
				monitor_mode = true;
				break;
			case 'P':
				psql_mode = true;
				break;
			case 'p':
				if (strcmp(optarg, "drop") == 0)
					first_occ_policy = POLICY_DROP;
				else if (strcmp(optarg, "accept") == 0)
					first_occ_policy = POLICY_ACCEPT;
				else if (strcmp(optarg, "ping") == 0)
					first_occ_policy = POLICY_PING;
				break;
			case 'R':
				cleanDatabase();
				reset = true;
				break;
			case 't':
				sleep_time = atoi(optarg);
				if(sleep_time <= 0) {
					fprintf(stderr, "Error: Bad sleep time\n");
					return 1;
				}
				break;
			default:
				print_help();
				return 1;
		}
	}

	spoof_detector = new SpoofDetector();
	spoof_detector->setup();
	spoof_detector->set_first_occ_policy(first_occ_policy);
	spoof_detector->set_monitor_mode(monitor_mode);

	if(empty) {
		readFirewallModule();
		cout << "Kernel data structure emptied." << endl;
	 	return 0;
	}

	if(psql_mode) {
		if(read_psql_confs()) {
			cout << "Cannot read psql.conf. Is it formatted correctly? e.g. dbname=ttls" << endl;
			return 1;
		}
		if(reset) reset_psql_db(pinfo);
	}

	printf("Will update database ever %zu seconds\n", sleep_time);
	do {
		t = time(0);
		thread t1(parseTask);
		t1.join();
		t = sleep_time - (time(0) - t);
		if(t > 0){
			cout << "Next update in " << t << " seconds..." << endl;
			sleep(t);
		}
	} while(sleep_time > 0);

	delete spoof_detector;
	return 0;
}
