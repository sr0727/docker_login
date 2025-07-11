FROM mysql:8.0

COPY ./shop_authenticationtbl.sql /docker-entrypoint-inotdb.d

ENV MYSQL_ROOT_PASSWORD=1234
ENV MYSQL_DATABASE=shop