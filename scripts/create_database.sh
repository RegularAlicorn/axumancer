if ! [ -e src/main.rs ]; then echo 'Start this file from your base folder'; exit; fi

mkdir -p db

if ! [ -e db/db_authentication.sqlite ]; then cat scripts/table_authentication.sql | sqlite3 db/db_authentication.sqlite; else echo 'Authentication db already exists.'; fi

