#include <iostream>
#include <sstream>
#include <pqxx/pqxx>
#include <ctime>
#include <string>
#include <sqlite3.h>
#include <unistd.h>
#include "psql_ops.h"
#include "fwall_parser.h"

using namespace std;
using namespace pqxx;

struct psql_db_info s_pinfo;

connection * open_connection(struct psql_db_info pinfo) {
	connection *C;

	try {
		stringstream ss;
		ss << "dbname = " << pinfo.dbname << " user = " << pinfo.user << \
			" password = " << pinfo.password << " hostaddr = " << pinfo.hostaddr;

		C = new connection(ss.str().c_str());
		if (C->is_open()) {
			cout << "Opened database: " << C->dbname() << endl;
		} else {
			cout << "Cannot open database" << endl;
			return NULL;
		}
	} catch (const exception &e) {
		cerr << e.what() << endl;
		return NULL;
	}

	return C;
}

// Example SQL string generated:
//
// BEGIN;
//
// CREATE TEMPORARY TABLE newvals(ip bigint, int ttl_1....);
//
// INSERT INTO newvals (ip) VALUES (123), (456)....;
//
// INSERT INTO ttls
// SELECT newvals.ip
// FROM newvals
// LEFT OUTER JOIN ttls ON (ttls.ip = newvals.ip)
// WHERE ttls.ip IS NULL;
//
// COMMIT;
//
// Postgresql version < 9.5 does not support ON CONFLICT, so this is a workaround.
// Works by creating a temporary table and only inserting the unique values to
// avoid conflicts. Then a big update is executed.
void update_psql_db(ttl_mappings *mappings, struct psql_db_info pinfo) {
	stringstream inserts_ss, updates_ss;

	connection *C = open_connection(pinfo);
	if(!C) return;

	// Build temporary table create statement
	inserts_ss << "BEGIN; CREATE TEMPORARY TABLE newvals(IP BIGINT);";

	inserts_ss << "INSERT INTO newvals (IP) VALUES (1)";

	for(pair<unsigned int, struct ip_info> element : *mappings) {
		updates_ss << "UPDATE " << pinfo.schema << "." << pinfo.table << " SET IP = IP";
		inserts_ss << ", (" << element.first << ")";
		for (int i = 0; i < 256; i++) {
			if(element.second.ttls[i] > 0) {
					updates_ss << ", TTL_" << i << " = TTL_" << i << " + " << element.second.ttls[i];
			}
		}
		updates_ss << " WHERE IP = " << element.first << ";";
	}

	inserts_ss << ";INSERT INTO " << pinfo.schema << "." << pinfo.table << "" << \
		" SELECT newvals.ip" << \
		" FROM newvals" << \
		" LEFT OUTER JOIN " << pinfo.schema << "." << pinfo.table << \
		" ON (" << pinfo.schema << "." << pinfo.table << ".ip = newvals.ip)" << \
		" WHERE " << pinfo.schema << "." << pinfo.table << ".ip IS NULL;" << \
		" COMMIT;";

	updates_ss << "COMMIT;";

	try {
		work W(*C);

		cout << "Inserting psql entries..." << endl;
		W.exec(inserts_ss.str().c_str());
		W.commit();

		work W2(*C);

		cout << "Updating psql TTLS..." << endl;
		W2.exec(updates_ss.str().c_str());
		W2.commit();


	} catch (const exception &e) {
		cerr << e.what() << endl;
	}

	C->disconnect();
}

// Callback function for the update_ipdb function.
// Void pointer should be of type pair<stringstream *, stringstream*>*
// where the first ss is inserts, and the second is updates.
// Only updates ttl's > 0.
static int scallback(void *vss_pair, int argc, char **argv, char **azColName) {
	pair<stringstream *, stringstream *> *ss_pair = static_cast<pair<stringstream *,stringstream *> *>(vss_pair);
	stringstream *inserts_ss = ss_pair->first;
	stringstream *updates_ss = ss_pair->second;
	int i, no_ttl;
	unsigned int ip = atoi(argv[0]);

	*inserts_ss << ", (" << ip << ")";
	*updates_ss << "UPDATE " << s_pinfo.schema << "." << s_pinfo.table << " SET TTL_1 = TTL_1";

	for(i = 3; i < argc; i++) {
		no_ttl = atoi(argv[i]);
		if(no_ttl > 0) {
			*updates_ss << ",TTL_" << i-2 << "=" << no_ttl;
		}
	}

	*updates_ss << " WHERE IP=" << ip << ";";

	return 0;
}

// This function selects everything from the sqlite database who's
// path is given by string path_to_db, and updates the postgresql
// accordingly.
void copy_ipdb(string path_to_db, struct psql_db_info pinfo) {
	stringstream select_ss, inserts_ss, updates_ss;
	int rc;
	char *zErrMsg = 0;
	sqlite3 *db;
	pair<stringstream *, stringstream *> ss_pair = make_pair(&inserts_ss, &updates_ss);
	connection *C = open_connection(pinfo);
	s_pinfo = pinfo;

	if(!C) return;

	rc = sqlite3_open("ipdb.db", &db);

	if(rc) {
		fprintf(stderr, "Can't open ipdb\n");
		return;
	}

	select_ss << "SELECT * FROM " << pinfo.table << ";";

	inserts_ss << "INSERT INTO " << pinfo.schema << "." << pinfo.table << " (IP) VALUES (1)";

	rc = sqlite3_exec(db, select_ss.str().c_str(), scallback, &ss_pair, &zErrMsg);
	if(rc != SQLITE_OK) {
		printf("SQLite error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}

	inserts_ss << ";"; //" ON CONFLICT DO NOTHING;";

	try {
		work W(*C);

		cout << "Inserting psql entries..." << endl;
		W.exec(inserts_ss.str().c_str());
		W.commit();
		cout << "Done." << endl;

		work W2(*C);

		cout << "Updating psql TTLS..." << endl;
		W2.exec(updates_ss.str().c_str());
		W2.commit();
		cout << "Done." << endl;
	} catch (const exception &e) {
		cerr << e.what() << endl;
	}

	C->disconnect();
}

int drop_table(connection *C, struct psql_db_info pinfo) {
	stringstream sql;

	sql << "DROP TABLE " << pinfo.schema << "." << pinfo.table << ";";

	try {
		work W(*C);

		W.exec(sql.str().c_str());
		W.commit();
		cout << "Table deleted successfully" << endl;
	} catch (const exception &e) {
		cerr << e.what() << endl;
		return 1;
	}

	return 0;
}

// SQL generated:
// CREATE TABLE data.ttls(IP BIGINT PRIMARY KEY NOT NULL, TTL_1 INT DEFAULT 0 ...
int create_table(connection *C, struct psql_db_info pinfo) {
	int i;
	stringstream ss;

	ss << "CREATE TABLE " << pinfo.schema << "." << pinfo.table << "(IP BIGINT PRIMARY KEY NOT NULL";
	for(i = 1; i < 256; i ++) {
		ss << ", TTL_" << i << " INT DEFAULT 0";
	}

	ss << ");";

	try {
		work W(*C);

		W.exec(ss.str().c_str());
		W.commit();
		cout << "Table created successfully" << endl;
	} catch (const exception &e) {
		cerr << e.what() << endl;
		return 1;
	}
	return 0;
}

void reset_psql_db(struct psql_db_info pinfo) {
	connection *C = open_connection(pinfo);

	if(!C) return;

	drop_table(C, pinfo);
	create_table(C, pinfo);

	C->disconnect();
}
