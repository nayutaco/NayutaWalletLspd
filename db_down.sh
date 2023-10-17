#!/bin/bash

files="postgresql/migrations/*.sql"
for f in $files; do
        if [ "`echo $f | grep 'down\.sql'`" ]; then
                echo "------------------------"
                echo "[$f]"
                psql -d lspdb -f $f
        fi
done

echo done!
