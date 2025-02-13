FROM alpine:3.21

WORKDIR /app

USER 0

ADD ./auto /app/auto
ADD ./conf /app/conf
ADD ./contrib /app/contrib
ADD ./docs /app/docs
ADD ./misc /app/misc
ADD ./src /app/src
ADD ./LICENSE /app/

RUN apk add --no-cache bash

RUN <<EOF bash
set -ex

apk add --no-cache build-base make openssl git zlib-dev openssl-dev pcre-dev
git clone https://github.com/GetPageSpeed/ngx_security_headers.git ngx_security_headers
git clone https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git ngx_http_substitutions_filter_module
git clone https://github.com/NorthRealm/ngx_stream_minecraft_forward_module.git ngx_stream_minecraft_forward_module
cp auto/configure .
./configure \
  --add-module=$(pwd)/ngx_security_headers \
  --add-module=$(pwd)/ngx_http_substitutions_filter_module \
  --add-module=$(pwd)/ngx_stream_minecraft_forward_module \
  --with-http_auth_request_module \
  --with-http_dav_module \
  --with-http_realip_module \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-pcre \
  --with-socks5 \
  --with-stream \
  --with-stream_realip_module \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module
make
apk del --no-cache make git
chmod +x objs/nginx
mkdir logs
touch logs/access.log
touch logs/error.log
objs/nginx -V
rm -rf ngx_security_headers
rm -rf ngx_http_substitutions_filter_module
rm -rf ngx_stream_minecraft_forward_module

cat << EOS > /docker-entrypoint.sh
#!/bin/sh

/app/objs/nginx -p /app -g "daemon off;"

EOS
chmod +x /docker-entrypoint.sh
EOF


EXPOSE 80
EXPOSE 443
EXPOSE 25565

ENTRYPOINT ["/docker-entrypoint.sh"]