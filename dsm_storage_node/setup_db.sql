-- Create DSM user and databases
CREATE USER dsm WITH PASSWORD 'dsm';

-- Create databases for each node
CREATE DATABASE dsm_storage_node1 OWNER dsm;
CREATE DATABASE dsm_storage_node2 OWNER dsm;
CREATE DATABASE dsm_storage_node3 OWNER dsm;
CREATE DATABASE dsm_storage_node4 OWNER dsm;
CREATE DATABASE dsm_storage_node5 OWNER dsm;

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE dsm_storage_node1 TO dsm;
GRANT ALL PRIVILEGES ON DATABASE dsm_storage_node2 TO dsm;
GRANT ALL PRIVILEGES ON DATABASE dsm_storage_node3 TO dsm;
GRANT ALL PRIVILEGES ON DATABASE dsm_storage_node4 TO dsm;
GRANT ALL PRIVILEGES ON DATABASE dsm_storage_node5 TO dsm;
