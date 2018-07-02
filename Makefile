all: cvesync

cvesync:
	go build -o cvesync github.com/shift/cvesync/main

install:
	mkdir -p /opt/cvesync/bin /opt/cvesync/etc /opt/cvesync/var
	cp cvesync /opt/cvesync/bin/
	chmod 755 /opt/cvesync/bin/cvesync
	cp ca.crt settings.json jira.json blacklist.txt rt.json jira.templ rt.templ cwec_v2.8.xml /opt/cvesync/etc/
	chmod -R 755 /opt/cvesync/etc
	cp cvesync.sqlite /opt/cvesync/var/
	chmod 755 /opt/cvesync/var/cvesync.sqlite

selinux:
	selinux/cvesync.sh

clean:
	rm cvesync

test:
	go test .

.PHONY: selinux
