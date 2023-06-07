#!/bin/bash

cd /tmp
wget https://nmap.org/dist/nmap-${NMAP_VERSION}.tgz -O nmap.tar.gz
tar -zxvf nmap.tar.gz
cd nmap-${NMAP_VERSION}

sed -i.bak '/  } else if (status == NSE_STATUS_TIMEOUT) {/i\    else {\
      if (readstrlen > 0)\
        svc->addToServiceFingerprint(probe->getName(), readstr, readstrlen);\
    }' service_scan.cc


# 删除匹配行后三行
sed -i.bak '/Never print FP if hardmatched/,+3d' service_scan.cc

# 误报规则删除
sed -i.bak 's#^match http m|\^HTTP/1\\\.1 400 Bad Request\\r\\nContent-Length: 40\\r\\nContent-Type: text/html\\r\\n\\r\\n<h1>400 Bad Request</h1>Bad request line| p/JBoss Enterprise Application Platform/ cpe:/a:redhat:jboss_enterprise_application_platform/##' nmap-service-probes

./configure --prefix=/usr/local/nmap --without-zenmap
make && make install
ln -s /usr/local/nmap/bin/nmap /usr/bin/nmap