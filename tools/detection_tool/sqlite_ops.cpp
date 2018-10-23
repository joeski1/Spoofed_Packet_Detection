#include <sqlite3.h>
#include <stdlib.h>
#include <sstream>
#include <string>
#include <iostream>
#include "sqlite_ops.h"

using namespace std;

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

// Drops the TCP and UDP tables
void dropTables(sqlite3 *db) {
	string sql;
	char *zErrMsg = 0;
	int rc;

	sql = "DROP TABLE TTLS;";

	rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);

	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} else printf("Table TTLS deleted successfully\n");
}

// Creates the TCP and UDP tables with initial values 0 for all TTLs
void createTables(sqlite3 *db) {
	string sql;
	stringstream ss;
	char *zErrMsg = 0;
	int rc, i;

	ss << "CREATE TABLE TTLS(IP UNSIGED INTEGER PRIMARY KEY NOT NULL, " \
	   << "AVERAGE_TTL INT DEFAULT 0, COUNT INT DEFAULT 0, TTL_1 INT DEFAULT 0";

	for(i = 2; i < 256; i++) {
		ss << ", TTL_" << i << " INT DEFAULT 0";
	}

	ss << ");";
	sql = ss.str();

	rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);

	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} else {
		printf("Table created successfully\n");
	}
}

//INSERT INTO TTLS (ip) VALUES (123), (456), (789);

void insertTTLS(sqlite3 *db, ttl_mappings *mappings) {
	stringstream ss;
	int rc;
	char *zErrMsg = 0;

	ss << "INSERT OR IGNORE INTO TTLS (ip) VALUES (0)";
	for (pair<unsigned int, struct ip_info> element : *mappings) {
		ss << ", (" << element.first << ")";
	}
	ss << ";";
	// cout << ss.str() << endl;
	// cout << "Executing inserts" << endl;
	rc = sqlite3_exec(db, ss.str().c_str(), callback, mappings, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
}

// UPDATE TTLS SET TTL_64 = TTL_64 + 3 WHERE IP = 123
void updateTTLS(sqlite3 *db, ttl_mappings *mappings) {
	stringstream ss;
	bool first = true;
	int rc, count, total, newAverage, newCount;
	char *zErrMsg = 0;

	ss << "BEGIN;";
	for (pair<unsigned int, struct ip_info> element : *mappings) {
		ss << "UPDATE TTLS SET ";
		first = true;
		count = 0;
		total = 0;
		for (int i = 0; i < 256; i++) {
			if(element.second.ttls[i] > 0) {
				count += element.second.ttls[i];
				total += element.second.ttls[i]*i;
				if(first) {	
					ss << "TTL_" << i << " = TTL_" << i << " + " << element.second.ttls[i];
					first = false;
				} else { 
					ss << ", TTL_" << i << " = TTL_" << i << " + " << element.second.ttls[i];
				}
			} 
		}
		newCount = element.second.count + count;
		// printf("new count: %d + %d = %d\n", element.second.count, count, newCount);
		if(count == 0) 	newAverage = element.second.averageTTL;
		else		newAverage = (element.second.averageTTL*element.second.count + total)/newCount;
		// printf("old average: %d. New Average: %d\n", element.second.averageTTL, newAverage);
		if(first) ss << " COUNT = " << newCount << ", AVERAGE_TTL = " << newAverage;
		else 	  ss << ", COUNT = " << newCount << ", AVERAGE_TTL = " << newAverage;
		ss << " WHERE IP = " << element.first << ";";
	}
	ss << "COMMIT;";
	// cout << ss.str() << endl;
	// cout << "Executing update statement" << endl;
	rc = sqlite3_exec(db, ss.str().c_str(), callback, mappings, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
}

// SELECT IP, AVERAGE_TTL, COUNT FROM TTLS WHERE IP IN (123, 456, 789);
void selectAveragesAndCount(sqlite3 *db, ttl_mappings *mappings, 
			    int (*tcallback)(void*,int,char**,char**)){
	int rc;
	stringstream ss;
	char *zErrMsg = 0;
	
	ss << "SELECT IP, AVERAGE_TTL, COUNT FROM TTLS WHERE IP IN (0";
	for (pair<unsigned int, struct ip_info> element : *mappings) {
		ss << ", " << element.first;
	}
	ss << ");";
	
	// cout << ss.str() << endl;
	// cout << "Executing select statement" << endl;
	rc = sqlite3_exec(db, ss.str().c_str(), tcallback, mappings, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
}

void cleanDatabase() {
	sqlite3 *db;
	int rc;

	rc = sqlite3_open("ipdb.db", &db);
	if(rc) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return;
	}
	dropTables(db);
	createTables(db);
	sqlite3_close(db);
}
