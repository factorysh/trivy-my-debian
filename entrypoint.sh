#!/bin/bash
if [ ! -e /data/debian_cve.json ];
then curl -o /data/debian_cve.json https://security-tracker.debian.org/tracker/data/json;
fi

exec "$@"
