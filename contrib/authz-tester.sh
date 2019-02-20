#!/bin/bash

user="user1"
version="1.39"
uri="/AuthZPlugin.AuthZReq"
port=8000

usage() { echo "usage: $0 [-u user] [-v version] [-r uri] host [port]" >&2; exit 0 ;} 
cmdline=$(getopt "u:v:r:h" "$@")
eval set -- $cmdline
while :; do
	case "$1" in
		-u) user="$2"; shift;;
		-v) version="$2"; shift;;
		-r) uri="$2"; shift;;
		-h) usage;;
		--) shift; break ;;
		*) echo "wrong arg: $1" >&2; exit 1;;
	esac
	shift;
done

if [ -z "$1" ]; then usage; else host=$1; fi
shift

if [ ! -z "$1" ]; then port="$2"; fi
shift


json='{"User":"'$user'","RequestURI":"/v'$version$uri'"}'
set -x
echo $(curl -vsfN -H "content-type: application/json" -X POST --data "$json" "http://$host:$port$uri")

