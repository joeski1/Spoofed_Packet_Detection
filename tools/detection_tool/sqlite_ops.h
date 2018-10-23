#ifndef SQLITE_OPS
#define SQLITE_OPS

#include "fwall_parser.h"
#include <sqlite3.h>

void updateTTLS(sqlite3 *db, ttl_mappings *mappings);
void insertTTLS(sqlite3 *db, ttl_mappings *mappings);
void selectAveragesAndCount(sqlite3 *db, ttl_mappings *mappings, int (*callback)(void*,int,char**,char**));
void cleanDatabase();

#endif
