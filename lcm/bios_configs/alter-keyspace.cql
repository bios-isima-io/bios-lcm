CONSISTENCY ALL
ALTER KEYSPACE system_auth WITH REPLICATION = {'class': 'NetworkTopologyStrategy', 'dc_rollup': '1', 'dc_signal': '1',  'dc_analysis': '1'};
ALTER KEYSPACE system_distributed WITH REPLICATION = {'class': 'NetworkTopologyStrategy', 'dc_rollup': '1', 'dc_signal': '1', 'dc_analysis': '1'};
ALTER KEYSPACE system_traces WITH REPLICATION = {'class': 'NetworkTopologyStrategy', 'dc_rollup': '1', 'dc_signal': '1', 'dc_analysis': '1'};
