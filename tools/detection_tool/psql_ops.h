#ifndef PSQL_OPS_H
#define PSQL_OPS_H

#include "fwall_parser.h"
#include <sqlite3.h>

struct psql_db_info {
	string schema;
	string table;
	string dbname;
	string user;
	string password;
	string hostaddr;		
};

void reset_psql_db(struct psql_db_info pinfo);
void copy_ipdb(std::string path_to_db, struct psql_db_info pinfo);
void update_psql_db(ttl_mappings *mappings, struct psql_db_info pinfo);

#endif
