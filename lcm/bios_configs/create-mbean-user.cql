CONSISTENCY ALL;
CREATE ROLE IF NOT EXISTS ${DB_JMX_USER} WITH PASSWORD = '${DB_JMX_PASSWORD}' AND SUPERUSER = false;
GRANT DESCRIBE ON ALL MBEANS TO ${DB_JMX_USER};
GRANT SELECT ON MBEAN 'org.apache.cassandra.db:type=StorageService' TO ${DB_JMX_USER};
GRANT EXECUTE ON MBEAN 'org.apache.cassandra.db:type=StorageService' TO ${DB_JMX_USER};
GRANT EXECUTE ON MBEAN 'org.apache.cassandra.db:type=EndpointSnitchInfo' TO ${DB_JMX_USER};
