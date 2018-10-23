#include <sqlite3.h>
#include <stdlib.h>
#include <sstream>
#include <string>
#include <iostream>
#include <math.h> 

using namespace std;

#define NIPQUAD(addr) \
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

int ttls[256] = {0}, hops[64] = {0}, ranges[64] = {0};
double ttl_probs[256] = {0}, hops_probs[64] = {0}, global_variance = 0;
int total, count = 0;

int fastAtoi(const char *str)
{
    int val = 0;
    while( *str ) {
        val = val*10 + (*str++ - '0');
    }
    return val;
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

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

static int count_callback(void *NotUsed, int argc, char **argv, char **azColName) {
	int i, no_ttl, exists = 0;

	for(i = 3; i<argc; i++) {
		no_ttl = fastAtoi(argv[i]);
		if(no_ttl > 0) {
			//printf("%s = %s(%d)\n", azColName[i], argv[i] ? argv[i] : "NULL", i-2);
			ttls[i-2] += no_ttl;
			total += no_ttl;
			exists = 1;
		}
   	}
	if(exists) count++;	
	return 0;
}

static int probability_callback(void *NotUsed, int argc, char **argv, char **azColName) {
	int i, no_ttl, cur_count = 0, cur_ttls[256] = {0};
	// int ip = fastAtoi(argv[0]);

	for(i = 3; i<argc; i++) {
		no_ttl = fastAtoi(argv[i]);
		if(no_ttl > 0) { 
			cur_count += no_ttl;
			cur_ttls[i-2] = no_ttl;
		}	
	}
	if(cur_count == 0) return 0;

	count++;

	for(i = 0; i < 255; i++) {
		if(cur_ttls[i] > 0) {
			ttl_probs[i] += ((double)cur_ttls[i])/((double)cur_count);
		}
	}
	return 0;
}

static int merge_callback(void *vss, int argc, char **argv, char **azColName) {
	pair<stringstream *, stringstream *> *ss_pair = (pair<stringstream *, stringstream *> *) vss;
	stringstream *ss_inserts = ss_pair->first;
	stringstream *ss_updates = ss_pair->second;
	int no_ttl, i;

	*ss_inserts << ", (" << argv[0] << ")";
	*ss_updates << "UPDATE TTLS SET TTL_255 = TTL_255";
	
	for(i = 3; i<argc; i++) { 
		no_ttl = fastAtoi(argv[i]);
		if(no_ttl > 0) {
			*ss_updates << ", TTL_" << i-2 << " = TTL_" << i-2 << "+" << no_ttl;
		}
		
	}
	*ss_updates << " WHERE IP = " << argv[0] << ";";
	return 0;
}

static int ranges_callback(void *vss, int argc, char **argv, char **azColName) {
	int i, high, low = 0, no_hop, cur_count = 0, cur_hops[64] = {0}, cur_total = 0;
	double square_sum = 0, cur_mean, cur_variance = 0;

	for(i = 3; i<67; i++) {
		no_hop = fastAtoi(argv[i]) + fastAtoi(argv[i+64]) + fastAtoi(argv[i+191]);
		if(no_hop > 0) { 
			cur_count += no_hop;
			cur_total += no_hop*(i-2);
			cur_hops[i-2] = no_hop;
			high = i-2;
		}	
	}

	if(cur_count < 2) return 0;
	
	cur_mean = cur_total/cur_count;

	// Calculating lower bound and variance
	for(i = 0; i < 64; i++) {
		if(cur_hops[i] > 0) { 
			for(int j = 0; j < cur_hops[i]; j++) {
				square_sum += pow(i - cur_mean, 2);
			}
			if(low == 0) {
				low = i;
			}
		}
	}
	
	
	ranges[high-low]++;
	cur_variance = square_sum/(cur_count - 1);
	global_variance = (count*global_variance + cur_variance)/(count+1);
	count++;

	// cout << "cur_variance: " << cur_variance << ". global variance: " << global_variance << endl;

	/*if((high-low) > 2) {
		int ip = fastAtoi(argv[0]); 
		cout << argv[0] << " with range " << high-low;
		printf(" (%u.%u.%u.%u)\n", NIPQUAD(ip));
		for(i = 0; i < 64; i++) {
			if(cur_hops[i] > 0) {
				cout << "	" << i << "x" << cur_hops[i] << endl;
			}
		}	
	}*/

	return 0;
}

void find_ranges_sql(sqlite3 *db) {
	int rc;
	stringstream ss;
	char *zErrMsg = 0;

	ss << "SELECT * FROM TTLS;";

	rc = sqlite3_exec(db, ss.str().c_str(), ranges_callback, 0, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}

	for(int i = 0; i < 64; i++) {
		cout << i << "," << ranges[i] << endl;
	}

	cout << "global_variance: " << global_variance << endl;
}

void probs_sql(sqlite3 *db) {
	int rc, i;
	stringstream ss;
	double p_total = 0;
	char *zErrMsg = 0;

	ss << "SELECT * FROM TTLS;";

	rc = sqlite3_exec(db, ss.str().c_str(), probability_callback, 0, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}

	for(i = 0; i < 256; i++) {
		ttl_probs[i] = ttl_probs[i]/count;
		cout << fixed << i << "," << ttl_probs[i] << endl;
	}

	for(i = 0; i < 64; i++) {
		hops_probs[i] = ttl_probs[i] + ttl_probs[i+64] + ttl_probs[i+191];	
		cout << fixed << i << "," << hops_probs[i] << endl;
		p_total += hops_probs[i];
	}
	cout << "TOTAL " << p_total << endl;
}

void count_sql(sqlite3 *db) {
	int rc, i;
	stringstream ss;
	char *zErrMsg = 0;

	ss << "SELECT * FROM TTLS;";

	rc = sqlite3_exec(db, ss.str().c_str(), count_callback, 0, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}

	for(i = 0; i < 64; i++) {
		hops[i] = ttls[i] + ttls[i+64] + ttls[i+191];
	}

	for(i = 0; i < 256; i++) { 
		cout << i << "," << ttls[i] << endl;
		// cout << i << "," << hops[i] << endl;
	}
	cout << "total packets:" << total << "(" << count << " unique)" << endl;
}


// Merge two databases 'ipdb.db' and 'ipdb2.db'
void merge_sql(sqlite3 *db) {
	int rc;
	char *zErrMsg = 0;
	sqlite3 *db2;
	stringstream ss, *ss_inserts, *ss_updates;

	rc = sqlite3_open("ipdb2.db", &db2);
	if(rc) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return;
	}
	
	ss_inserts = new stringstream;
	ss_updates = new stringstream;
	ss << "SELECT * FROM TTLS;";

	*ss_inserts << "INSERT OR IGNORE INTO TTLS (ip) VALUES (0)";

	pair<stringstream *, stringstream *> ss_pair = make_pair(ss_inserts, ss_updates);
	rc = sqlite3_exec(db, ss.str().c_str(), merge_callback, (void *) &ss_pair, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}

	*ss_inserts << ";";
	
	rc = sqlite3_exec(db2, ss_inserts->str().c_str(), callback, 0, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}

	rc = sqlite3_exec(db2, ss_updates->str().c_str(), callback, 0, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
}

int main (int argc, const char* argv[]) {
	sqlite3 *db;
	int rc;

	rc = sqlite3_open("ipdb.db", &db);
	if(rc) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return 0;
	}

	// count_sql(db);
	// merge_sql(db);
	// probs_sql(db);
	find_ranges_sql(db);
	return 0;
}
