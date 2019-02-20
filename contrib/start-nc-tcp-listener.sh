#!/bin/sh
error() { echo ERROR: "$*" >&2; exit 1; }
warning() { echo WARNING: "$*" >&2; }
info() { echo INFO: "$*" >&2; } 

if [ $UID -ne 0 ]; then
	error "root previlege needed"
fi
rm -f /tmp/docker-r??.log
warning "check /tmp/docker-re?.log for details"
nc -k -l -C -c "tee -a /tmp/docker-req.log | /home/ec2-user/projects/authz/docker-authz-simple.sh | tee -a /tmp/docker-res.log" 8080

