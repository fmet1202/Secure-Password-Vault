#include "securevault.h"

PGconn* g_db_conn = NULL;

bool db_init(const char* conninfo) {
    g_db_conn = PQconnectdb(conninfo);
    if (PQstatus(g_db_conn) != CONNECTION_OK) {
        printf("[DB ERROR] Connection to database failed: %s\n", PQerrorMessage(g_db_conn));
        PQfinish(g_db_conn);
        g_db_conn = NULL;
        return false;
    }
    printf("[DB LOG] Successfully connected to PostgreSQL.\n");
    return true;
}

PGconn* db_get_conn(void) {
    return g_db_conn;
}

void db_close(void) {
    if (g_db_conn) {
        PQfinish(g_db_conn);
        g_db_conn = NULL;
        printf("[DB LOG] Database connection closed.\n");
    }
}
