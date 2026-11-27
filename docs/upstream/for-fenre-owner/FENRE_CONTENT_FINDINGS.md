# Findings in the Fenre content catalogue, found while building SUNavigator

This is a courtesy report. It is written to be read on its own and nothing in it has been filed as an issue.
Use as much or as little of it as is useful; every item says how to reproduce it and what would fix it.

* Catalogue checked: Fenre `main` at commit `0e21f019` (16,726 use cases, 19,771 searches counting the CIM variants).
* Tool: SUNavigator 0.12.1 (https://github.com/cagdaskarabag/su_navigator, Apache-2.0), `tools/fenre_report.py` (SPL lint, `sunavigator/lib/splunk_ucm/spl/lint.py`) and the control-test campaign (`tools/controltest_campaign.py`).
* Environment: Splunk Enterprise 10.2.9, no add-ons installed. Every rule below fires only for a construct that was shown to be wrong on that version. For rules `L002` to `L005` the flagged searches were also sent to Splunk's own parser (`/services/search/parser`) and all of them were rejected. `L001` is silent in the parser (Splunk accepts the search and returns nothing), so it is shown by the one-line check in its section.
* Counting: 155 findings in 141 searches. A search counts once per rule however often the rule fires in it.

## Part A. SPL that Splunk rejects or that cannot match

| Rule | Problem | Searches | Findings |
|---|---|---|---|
| L001 | An eval function used as a search term | 80 | 88 |
| L002 | `timechart` with more than one split-by field | 56 | 56 |
| L003 | `match`, `like` or `cidrmatch` with the wrong number of arguments | 1 | 1 |
| L004 | Regex ending in a single backslash inside an eval string | 3 | 7 |
| L005 | Time modifier that snaps to a number of units | 1 | 1 |
| L006 | Regex with an escape PCRE2 does not support | 2 | 2 |

The same rows, one per finding, are in `fenre_content_findings.csv`.

### L001 An eval function used as a search term

* Why it is wrong: `search` (and the implicit search at the start of a query) does not evaluate eval functions. `match(...)`, `like(...)` and the others are read as plain words, so the clause matches nothing, and under `NOT` it matches everything. Splunk reports no error.
* Suggested fix: Move the condition into `| where` or `| eval` after the base search, for example `index=x sourcetype=y | where match(_raw, "pattern")`.

* Check it yourself: run `index=_internal | head 5 | search match(_raw, "nothing_like_this")` and then `index=_internal | head 5 | search NOT match(_raw, "nothing_like_this")`. The first returns no events and the second returns all five, because the call is searched for as text and never evaluated.

By function (findings): `match` 62, `like` 12, `lower` 5, `isnotnull` 4, `cidrmatch` 2, `isnull` 2, `upper` 1

| Use case | Title | Search | Command | Construct |
|---|---|---|---|---|
| UC-2.6.30 | MCS Provisioning and Identity Disk Health | primary | `search` | `match(_raw, "(?i)identity\|prep\|snapshot\|MCS\|Provision")` |
| UC-2.6.31 | Citrix Zone Topology and Zone Preference Failover | primary | `search` | `match(_raw, "(?i)zone\|failover\|preferred\|registration\|chassis\|data.?store\|inter.?zone")` |
| UC-2.6.32 | Hypervisor Connection Health Monitoring | primary | `search` | `match(_raw, "(?i)host(ing)?\s*connection\|hypervisor\|vCenter\|Nutanix\|XenServer\|scvmm\|cert\|ssl\|storage\|connecti…` |
| UC-2.6.33 | Citrix Autoscale Capacity Events | primary | `search` | `match(_raw, "(?i)autoscale\|power.?on\|turn.?on\|turn.?off\|scale.?in\|scale.?out\|power.?action\|capaci")` |
| UC-2.6.34 | Maintenance Mode and Drain Operations Tracking | primary | `search` | `match(_raw, "(?i)Maintenance\|drain\|suspend")` |
| UC-2.6.35 | Pre-Launch and Lingering Session Management | primary | `search` | `match(_raw, "(?i)pre[\s-]*launch\|lingering\|ghost\|idle\|disc")` |
| UC-2.6.36 | Session Reliability and Auto Client Reconnect | primary | `search` | `match(_raw, "(?i)session reliability\|reconnect\|WCF\|keep.?alive\|auto.?client\|ACR\|ICA.*reset\|edt\|tcp.*(drop\|res…` |
| UC-2.6.38 | Universal Print Server Health and Printing Failures | primary | `search` | `match(_raw, "(?i)Citrix.*Print\|Universal Print\|spooler\|CtxPrint\|render\|driver\|UPS")` |
| UC-2.6.39 | USB and Peripheral Redirection Failures | primary | `search` | `match(_raw, "(?i)USB\|TWAIN\|WIA\|redirect\|peripheral\|smart.?card\|scard\|clipboard\|mapped drive\|clpb\|device.*(fai…` |
| UC-2.6.40 | Citrix App Layering Health and Layer Attach Status | primary | `search` | `match(_raw, "(?i)App\s*Layer\|layering\|unifl\|svmgr\|ELM\|layer (attach\|mount\|roll\|package\|not found\|fail\|cache)")` |
| UC-2.6.41 | FSLogix and Profile Container Health | primary | `search` | `match(_raw, "(?i)FSLogix\|frx\|profile\|containe\|VHDX\|VHD \|reparse\|reconnect\|load.*fail\|attach.*fail\|size\|quota\|…` |
| UC-2.6.42 | Citrix Configuration Change Audit Trail | primary | `search` | `match(_raw, "(?i)BrokerPowerShell\|CVAD\|XD.*Catalog\|XenDesktop\|Studio\|Publish\|Delivery.?Group\|Machine.?Catalog…` |
| UC-2.6.42 | Citrix Configuration Change Audit Trail | primary | `search` | `match(_raw, "(?i)admin\|audit\|publish\|unpublish\|add.?desktop\|change.?entitlement\|polic\|Studio")` |
| UC-2.6.45 | Machine Boot Storm Detection and Mitigation | primary | `search` | `match(_raw, "(power.?on\|start\|registration\|boot)", "i")` |
| UC-2.6.51 | Citrix StoreFront Server IIS Health | primary | `search` | `like(lower(cs_uri_stem), "%citrix%")` |
| UC-2.7.3 | Proxmox VE Cluster Quorum Loss Detection from Corosync and pmxcfs Sig… | primary | `search` | `match(lower(_raw), "(?i)quorum\|qdevice\|not quorate\|lost.*quorum\|split.?brain\|totem.*fault\|ring.*fault")` |
| UC-2.8.11 | oVirt External Network Provider (OpenStack Neutron) Sync Errors | primary | `search` | `match(lower(_raw), "(?i)openstack\|neutron\|external.?network\|provider")` |
| UC-2.9.7 | OpenStack Nova Scheduler Retry and Placement Filter Exhaustion Audit | primary | `search` | `match(lower(_raw), "(?i)scheduler\|retrying\|no valid host\|filter")` |
| UC-2.9.12 | OpenStack Keystone Federation IdP Login and Mapping Failures | primary | `search` | `match(lower(_raw), "(?i)federat\|saml\|oidc\|mapped")` |
| UC-3.1.1 | Container Crash Loops | primary | `search` | `match(_raw, "(?i)oom-kill\|Out of memory\|Killed process")` |
| UC-3.1.2 | Container OOM Kills | primary | `search` | `match(_raw, "(?i)Memory cgroup out of memory")` |
| UC-3.3.14 | OpenShift OAuth Server Authentication Flow Failures, IdP Backend Erro… | primary | `search` | `match(lower(_raw),"authenticationfailed\|identityproviderconfigerror\|oauthservererror\|tokenissuedfailed\|oauth\…` |
| UC-5.2.43 | Juniper SRX Cluster Failover Events (Juniper SRX) | primary | `search` | `lower(process)` |
| UC-5.2.43 | Juniper SRX Cluster Failover Events (Juniper SRX) | primary | `search` | `match(_raw, "(?i)chassis cluster\|redundancy group\|RG-\d+\|failover\|switchover")` |
| UC-5.2.44 | FortiGate Security Fabric Health Monitoring (Fortinet) | primary | `search` | `lower(_raw)` |
| UC-5.2.44 | FortiGate Security Fabric Health Monitoring (Fortinet) | primary | `search` | `match(_raw, "(?i)FortiManager\|FortiAnalyzer\|authorization failed\|certificate.*fabric")` |
| UC-5.2.45 | FortiGate SD-WAN Health Check and SLA Monitoring (Fortinet) | primary | `search` | `match(_raw, "(?i)sd-wan\|sdwan")` |
| UC-5.3.23 | Citrix ADC AppFlow Export Health | primary | `search` | `match(_raw, "(?i)flow.*(export\|discard)")` |
| UC-5.4.35 | Aruba Air Monitor — WIDS/WIPS Events (HPE Aruba) | primary | `search` | `match(_raw, "(?i)(rogue\|evil.twin\|ad-hoc\|deauth\|disassoc).*(flood\|detected\|attack\|alert)")` |
| UC-5.7.14 | Geo-IP Flow Enrichment and Unexpected Country Detection | primary | `search` | `cidrmatch("10.0.0.0/8", dest)` |
| UC-5.7.18 | DNS-over-HTTPS / DNS-over-TLS Flow Identification | primary | `search` | `upper(protocol)` |
| UC-5.14.43 | Traefik Entrypoint Open Connections | primary | `search` | `match(metric_name, "traefik_entrypoint_open_connections")` |
| UC-7.1.52 | MongoDB Index Build Progress via CurrentOp | primary | `search` | `match(_raw,"createIndexes")` |
| UC-7.1.64 | ClickHouse Background Pool Saturation (Merges vs Mutations) | primary | `search` | `match(metric,"Merge")` |
| UC-7.1.81 | Snowflake Row Access Policy and Dynamic Masking Evidence | primary | `search` | `match(_raw,"(?i)row access policy")` |
| UC-7.5.22 | Snowflake Schema Object DDL from Query History | primary | `search` | `match(QUERY_TEXT,"(?i)^(create\|alter\|drop)\s+(table\|view\|schema\|warehouse\|pipe\|stage\|task\|stream)")` |
| UC-9.2.12 | LDAP Referral Chaining Monitoring | primary | `search` | `like(_raw,"%referral%")` |
| UC-9.3.16 | Token Endpoint Rate Limiting | primary | `search` | `like(_raw,"%rate limit%")` |
| UC-9.5.4 | Okta Admin Console Changes | primary | `search` | `like(eventType,"system.org%")` |
| UC-9.5.12 | Okta API Rate Limit Monitoring | primary | `search` | `like(lower(_raw),"%rate limit%")` |
| UC-10.11.102 | CrowdStrike File Integrity Monitoring Alerts | primary | `search` | `match(path, "/etc/.*")` |
| UC-10.12.20 | Breach Notification Readiness Assessment | primary | `search` | `match(body,"(?i)(ssn\|mrn\|diagnosis)")` |
| UC-10.13.11 | Connection Duration Outliers (CIM) | primary | `search` | `isnotnull(duration)` |
| UC-12.7.14 | Control-M Calendar-Based Scheduling Conflict Detection | primary | `search` | `match(lower(action),"(?i)create\|update\|delete")` |
| UC-13.1.2 | Splunk Scheduled and Ad-hoc Search Concurrency Saturation, User-Quota… | primary | `search` | `match(_raw, "(?i)dispatch_search_finalize\|TERM_REASON\|quota_exhausted\|reap\|reaper\|srchDiskQuota\|srchTimeWin")` |
| UC-13.1.8 | Splunk Deployment Server Health, Serverclass Distribution Coverage, F… | primary | `search` | `match(_raw,"(?i)reload\|state\|checksum\|exception")` |
| UC-13.1.12 | Splunk HTTP Event Collector (HEC) Endpoint Health, Token Misuse, Per-… | primary | `search` | `like(uri_path,"/services/collector%")` |
| UC-13.1.12 | Splunk HTTP Event Collector (HEC) Endpoint Health, Token Misuse, Per-… | primary | `search` | `match(uri_path,"^/services/collector")` |
| UC-13.1.27 | Splunk Web UI Errors (_internal) | primary | `search` | `match(_raw,"(?i)(error\|exception\|timeout)")` |
| UC-13.2.7 | ITSI Predictive Service Health Score, Forecast Horizon Accuracy, and … | primary | `search` | `match(lower(_raw),"servicehealthscore")` |
| UC-13.2.8 | ITSI Glass Table NOC Display Render Latency, Widget Refresh Stability… | primary | `search` | `match(lower(savedsearch_id),"glasstable")` |
| UC-13.2.16 | ITSI Backup Set Integrity | primary | `search` | `match(_raw,"(?i)(checksum\|verify failed)")` |
| UC-13.5.7 | Splunk APM Service Map Health (RED Metrics: Rate, Errors, Duration) w… | primary | `search` | `match(lower(metric_name),"^spans\.count$")` |
| UC-13.5.12 | Splunk Observability Cloud Detector Health | primary | `search` | `match(lower(message),"detector\|mute")` |
| UC-13.7.6 | Fluent Bit Output Plugin Flush Latency P95 Tail-Pain Detection, Per-D… | primary | `search` | `match(_raw,"/services/collector")` |
| UC-14.6.20 | Unknown Protocol on OT VLAN Detection | primary | `search` | `like(vlan_name,"OT-%")` |
| UC-14.6.20 | Unknown Protocol on OT VLAN Detection | primary | `search` | `cidrmatch("10.0.0.0/8",id.orig_h)` |
| UC-16.1.21 | War Room Activation Tracking | primary | `search` | `match(raw,"(?i)bridge\|war room\|command center")` |
| UC-18.2.3 | VMware NSX Segment (Logical Switch) Health: Operational State, VNI Bi… | primary | `search` | `match(lower(_raw),"(?i)(segment\|logical.?switch\|vni\|replication\|mac_count\|segment.?port\|oper_state\|realized)")` |
| UC-18.2.4 | VMware NSX Edge Transport Node Performance: North-South Gateway Throu… | primary | `search` | `match(lower(_raw),"(?i)(bgp\\[neighbor\\]\|lb\\[virtual_server\\]\|ipsec\|charon\|ikev2)")` |
| UC-18.2.11 | NAT Rule Utilization — VMware NSX Policy Tier-0 and Tier-1 NAT Sessio… | primary | `search` | `match(lower(_raw),"(?i)edge-nat-(info\|drop\|session-limit)")` |
| UC-18.2.12 | VMware NSX Tier-0 and Tier-1 Gateway HA Failover Events, Role Transit… | primary | `search` | `match(lower(_raw),"(?i)(ha_state\|failover\|standby\|preempt\|service.?router\|logical.?router\|tier[-_ ]?[01])")` |
| UC-18.2.13 | NSX Manager Cluster Health | primary | `search` | `match(lower(_raw),"(?i)(cluster.?status\|corfu\|vip\|ccp\|reverse.?proxy\|quorum\|manager.?service\|policy.?service\|…` |
| UC-19.1.31 | Fabric Interconnect HA Cluster State | primary | `search` | `like(code, "E4196%")` |
| UC-19.1.31 | Fabric Interconnect HA Cluster State | primary | `search` | `match(_raw, "(?i)election\|primary now\|subordinate now\|cluster lead\|split.?brain")` |
| UC-21.1.8 | Generator Trip Event Correlation | primary | `search` | `match(_raw,"(?i)trip\|generator")` |
| UC-21.8.7 | Customer Trouble Ticket Mean Time to Resolution | primary | `search` | `lower(status)` |
| UC-21.10.1 | Claims Processing Cycle Time Monitoring | primary | `search` | `lower(status)` |
| UC-22.2.50 | NIS2 Art.21/22 — Critical supplier risk, SBOM exposure and vendor acc… | primary | `search` | `lower(STATUS)` |
| UC-22.2.51 | NIS2 Art.12/21 secure development and vulnerability disclosure eviden… | primary | `search` | `match(actor,"^(svc-\|github-app)")` |
| UC-22.2.52 | NIS2 Art.21 access, HR security, privileged accounts, MFA and secure … | primary | `search` | `isnotnull(Termination_Date)` |
| UC-22.2.53 | NIS2 Art.21 business continuity, backup restore and physical-environm… | primary | `search` | `isnull(last_success_epoch)` |
| UC-22.2.56 | NIS2 evidence integrity, certification and standards crosswalk control | primary | `search` | `isnull(hash_verified)` |
| UC-22.2.56 | NIS2 evidence integrity, certification and standards crosswalk control | primary | `search` | `match(lower(validation_note),"(fail\|mismatch\|expired)")` |
| UC-22.2.56 | NIS2 evidence integrity, certification and standards crosswalk control | primary | `search` | `like(reason,"%quota%")` |
| UC-22.5.7 | MiFID II Clock Synchronization and Timestamp Quality for Reporting | primary | `search` | `isnotnull(reported_event_epoch_ms)` |
| UC-22.6.9 | ISMS Policy Acknowledgment and Version Drift in Confluence or SharePo… | primary | `search` | `match(object_name,"(?i)information.security.policy")` |
| UC-22.9.4 | Regulatory Incident Response Time Trending | primary | `search` | `like(rule_name,"%compliance%")` |
| UC-22.11.63 | Daily Log Review Workflow — PCI Queue Ticket Closure SLA | primary | `search` | `like(rule_name,"%PCI%")` |
| UC-22.13.47 | Data Preservation During Recovery Activities | primary | `search` | `match(action,"(?i)clean")` |
| UC-22.13.58 | BCSI Storage Location Inventory vs. Observed Disk Paths | primary | `search` | `match(path,"(?i)one-line\|relay\|settings\|cyber")` |
| UC-22.14.53 | Configuration Change Control — Unauthorized Firewall Rule Adds | primary | `search` | `match(_raw,"(?i)commit")` |
| UC-22.15.16 | Certificate-Based OPC-UA Logon Failures and Weak Trust Stores | primary | `search` | `match(_raw,"(?i)BadCertificate\|issuer\|untrusted")` |
| UC-22.15.42 | High-Rate Modbus Exception Responses (Potential DoS) | primary | `search` | `isnotnull(exception_code)` |
| UC-22.15.44 | Redundant Controller Failover During Attack Window | primary | `search` | `match(severity,"(?i)^high")` |
| UC-22.27.28 | Cyber Essentials boundary firewall configuration evidence | primary | `search` | `match(_raw,"policy")` |
| UC-22.31.3 | Australian Privacy Principles compliance monitoring | primary | `search` | `match(object,"(?i)de_identified")` |
| UC-23.4.1 | Workday Employee Attrition Risk and Voluntary Turnover Prediction | primary | `search` | `like(lower(tostring(Termination_Reason)),"voluntary%")` |

### L002 `timechart` with more than one split-by field

* Why it is wrong: `timechart` takes a single `by` field. A comma or a space separated list makes Splunk reject the search.
* Suggested fix: Use one field, or aggregate with `bin _time span=...` and `stats ... by _time, a, b`.

| Use case | Title | Search | Command | Construct |
|---|---|---|---|---|
| UC-2.6.58 | Citrix Analytics for Performance Data Export | primary | `timechart` | `by reason, user_principal` |
| UC-2.6.62 | Citrix Workspace Service Feed Availability | primary | `timechart` | `by issue, store_name` |
| UC-2.6.66 | Citrix Endpoint Management App Distribution Failures | primary | `timechart` | `by cat, plat` |
| UC-2.6.68 | Citrix Endpoint Management Remote Wipe/Lock Action Tracking | primary | `timechart` | `by action, outcome` |
| UC-6.1.22 | Fibre Channel Port Error Rate (Array) | primary | `timechart` | `by array_name, port_id` |
| UC-6.1.23 | LUN Latency Trending | primary | `timechart` | `by lun_id, array_name` |
| UC-6.1.27 | MDS Inter-Switch Link (ISL) Utilization | primary | `timechart` | `by switch, port` |
| UC-6.1.54 | NetApp ONTAP NVMe-oF namespace latency versus FC or iSCSI LUN latency | primary | `timechart` | `by proto, instance_name` |
| UC-6.1.77 | Pure Storage FlashBlade NFS latency by client and export path | primary | `timechart` | `by client, exp` |
| UC-6.2.47 | TrueNAS NFS export latency and RPC slow operations | primary | `timechart` | `by client, export_path` |
| UC-6.4.12 | DFS Replication Backlog and Connectivity Health | primary | `timechart` | `by replication_group, member` |
| UC-6.4.13 | NFS Export Capacity and Client Load | primary | `timechart` | `by export_path, host` |
| UC-6.4.15 | File Server Capacity Trending | primary | `timechart` | `by host, instance` |
| UC-7.1.24 | PostgreSQL Connection Pool Monitoring (PgBouncer) | primary | `timechart` | `by database, pool_mode` |
| UC-7.2.16 | DynamoDB Throttling Events | primary | `timechart` | `by TableName, Operation` |
| UC-7.3.1 | RDS/Aurora Performance Insights | primary | `timechart` | `by metric_name, DBInstanceIdentifier` |
| UC-7.3.9 | Azure Cosmos DB RU Consumption | primary | `timechart` | `by DatabaseName, CollectionName` |
| UC-7.3.12 | Azure SQL Database DTU Exhaustion | primary | `timechart` | `by database_name, elastic_pool_name` |
| UC-7.3.16 | Azure SQL Managed Instance Resource Utilization | primary | `timechart` | `by metric_name, resource_name` |
| UC-7.4.2 | Cluster Scaling Events | primary | `timechart` | `by event_name, warehouse_name` |
| UC-7.4.11 | Redshift Query Queue Depth | primary | `timechart` | `by ClusterIdentifier, QueueName` |
| UC-7.4.15 | Azure Synapse Analytics SQL Pool Performance | primary | `timechart` | `by metric_name, resource_name` |
| UC-7.4.17 | ClickHouse Active Data Parts Growth | primary | `timechart` | `by database, table` |
| UC-7.4.19 | PostgreSQL Database Size Growth Trend | primary | `timechart` | `by datname, host` |
| UC-7.4.20 | Cassandra Cluster Load per Node Trending | primary | `timechart` | `by address, cluster_name` |
| UC-7.4.21 | Redis used_memory Headroom vs maxmemory | primary | `timechart` | `by host, role` |
| UC-7.5.6 | Solr Query Cache Hit Ratio | primary | `timechart` | `by core, metric_path` |
| UC-8.1.16 | Web Server Thread Pool Exhaustion | primary | `timechart` | `by host, sourcetype` |
| UC-8.1.75 | Apache Tomcat Thread Pool Exhaustion (activeThreads vs maxThreads) | primary | `timechart` | `by host, mbean` |
| UC-8.2.6 | Connection Pool Monitoring | primary | `timechart` | `by host, pool_name` |
| UC-8.2.11 | PHP-FPM Pool Monitoring | primary | `timechart` | `by host, pool` |
| UC-8.2.12 | Tomcat JMX Thread Pool Utilization | primary | `timechart` | `by host, connector_name` |
| UC-8.2.13 | WildFly / JBoss Datasource Pool Usage | primary | `timechart` | `by host, data_source` |
| UC-8.2.18 | Tomcat Active Session Count | primary | `timechart` | `by host, context_path` |
| UC-8.3.1 | Consumer Lag Monitoring | primary | `timechart` | `by consumer_group, topic` |
| UC-8.3.2 | Queue Depth Trending | primary | `timechart` | `by queue_name, vhost` |
| UC-8.3.11 | RabbitMQ Queue Monitoring | primary | `timechart` | `by vhost, name` |
| UC-8.3.13 | Kafka Consumer Lag Monitoring (Consumer Group) | primary | `timechart` | `by consumer_group, topic` |
| UC-8.3.15 | Azure Service Bus Dead Letter Monitoring | primary | `timechart` | `by EntityName, SubscriptionName` |
| UC-8.4.11 | AWS API Gateway 4xx/5xx Trends | primary | `timechart` | `by ApiName, Stage, metric_name` |
| UC-8.4.17 | PHP-FPM Active Worker Saturation Versus max_children | primary | `timechart` | `by pool, host` |
| UC-8.4.22 | Tomcat Connector Connection Count Versus maxConnections | primary | `timechart` | `by host, connector_name` |
| UC-8.4.31 | PHP-FPM Active Workers Approaching max_children Saturation | primary | `timechart` | `by pool, host` |
| UC-8.4.32 | PHP-FPM Listen Queue Length Spike Detection | primary | `timechart` | `by pool, host` |
| UC-8.4.37 | PHP-FPM max_children Reached and 503 Correlation | primary | `timechart` | `by pool, host` |
| UC-8.5.31 | ActiveMQ Dead Letter Queue (DLQ) Accumulation | primary | `timechart` | `by dest, broker_name` |
| UC-8.5.37 | ActiveMQ Durable Subscriber Offline Backlog Growth | primary | `timechart` | `by dest, broker_name` |
| UC-8.6.31 | RabbitMQ Message Redelivery Rate Spike | primary | `timechart` | `by vhost, name` |
| UC-13.1.16 | Parsing Queue Health (_internal) | primary | `timechart` | `by host, name` |
| UC-13.1.40 | Per-Process CPU and Memory Trending (_introspection) | primary | `timechart` | `by data.process_type, host` |
| UC-13.2.36 | Azure Log Analytics Workspace Ingestion Health | primary | `timechart` | `by metric_name, resource_name` |
| UC-15.4.4 | APC PDU SNMP Per-Outlet Power Draw Trending | primary | `timechart` | `by pdu_name, outlet` |
| UC-15.5.8 | PoE Switch Port Power Draw Monitoring for CCTV Cameras | primary | `timechart` | `by port, switch_name` |
| UC-20.1.9 | Predictive Disk / Volume Exhaustion | primary | `timechart` | `by filesystem, host` |
| UC-20.2.17 | Storage Capacity Forecast by Tier | primary | `timechart` | `by storage_system, tier` |
| UC-22.15.43 | PLC CPU Load and Scan Cycle Degradation | primary | `timechart` | `by host, metric_name` |

### L003 `match`, `like` or `cidrmatch` with the wrong number of arguments

* Why it is wrong: These functions take exactly two arguments. A third argument (for example the flags string `"i"`) makes Splunk reject the search.
* Suggested fix: Put the flags inside the pattern: `match(field, "(?i)pattern")`.

| Use case | Title | Search | Command | Construct |
|---|---|---|---|---|
| UC-2.6.44 | VDA Disk IOPS and Write Cache Utilization | primary | `where` | `match(VolumeName, "Cache\|WCD\|MCS\|WriteCache\|PVS\|Differencing", "i")` |

### L004 Regex ending in a single backslash inside an eval string

* Why it is wrong: An eval string is unescaped once before the regex sees it, so a regex backslash needs four backslashes in the SPL. `"^.*\\"` leaves one backslash, which is an incomplete escape; Splunk rejects the search.
* Suggested fix: Write the end of the string as `"...\\\\"` (four backslashes).

| Use case | Title | Search | Command | Construct |
|---|---|---|---|---|
| UC-1.2.29 | Registry Run Key Modification (Persistence) | primary | `eval` | `replace(TargetObject,"^.*\\","")` |
| UC-1.2.29 | Registry Run Key Modification (Persistence) | primary | `eval` | `replace(registry_key_lc,"^(hklm\|hku\\[^\\]+)\\","")` |
| UC-1.2.29 | Registry Run Key Modification (Persistence) | primary | `where` | `match(registry_key_lc,"^(hklm\|hku\\[^\\]+)\\")` |
| UC-1.2.66 | Sysmon Executable or Script Creation in Selected User-Writable Paths | primary | `eval` | `match(target_filename,"^.:\\users\\[^\\]+\\appdata\\local\\temp\\")` |
| UC-1.2.119 | Sysmon Run and RunOnce Registry Value Sets | primary | `eval` | `replace(target_object,"^.*\\","")` |
| UC-1.2.119 | Sysmon Run and RunOnce Registry Value Sets | primary | `eval` | `match(registry_key_lc,"^hklm\\")` |
| UC-1.2.119 | Sysmon Run and RunOnce Registry Value Sets | primary | `eval` | `replace(registry_key_lc,"^(hklm\|hku\\[^\\]+)\\","")` |

### L005 Time modifier that snaps to a number of units

* Why it is wrong: `-6h@5m` is not valid. `@` snaps to one unit. `tstats` rejects the search and a plain search silently selects no events.
* Suggested fix: Snap to one unit, for example `-6h@m`, and use `span=5m` in `bin`, `tstats` or `timechart` for 5-minute buckets.

| Use case | Title | Search | Command | Construct |
|---|---|---|---|---|
| UC-3.2.1 | Kubernetes Pod Container Restart Churn and Rolling Restart-Rate Anoma… | primary | `tstats` | `earliest=-6h@5m` |

### L006 Regex with an escape PCRE2 does not support

* Why it is wrong: After the eval string is unescaped, `\u`, `\U`, `\l`, `\L` and `\F` remain in the regex, usually a Windows path written `"^.:\\users\\"`. PCRE2 does not support them and Splunk rejects the search.
* Suggested fix: Write four backslashes for each literal backslash: `"^.:\\\\users\\\\"`.

| Use case | Title | Search | Command | Construct |
|---|---|---|---|---|
| UC-1.2.29 | Registry Run Key Modification (Persistence) | primary | `eval` | `replace(registry_key_lc,"^\\registry\\user","hku")` |
| UC-1.2.66 | Sysmon Executable or Script Creation in Selected User-Writable Paths | primary | `eval` | `match(target_filename,"^.:\\users\\[^\\]+\\appdata\\local\\temp\\")` |

## Part B. Findings from running the fixtures

SUNavigator ran the events of 94 fixtures through each use case's own SPL on a lab with no add-ons and compared the result with the fixture's manifest. A defect is listed only when it holds without any add-on, or when it was shown to hold with the add-on's fields emulated. Fixture and manifest names refer to the files in `samples/` and `content/`.

| ID | Use cases | Defect | Kind |
|---|---|---|---|
| F-01 | UC-1.1.1 | Manifest cannot pass: the SPL returns one aggregated row with other column names | manifest vs SPL |
| F-02 | UC-1.1.8 | Fixture is below the SPL's own threshold, `min_count` is unreachable | fixture vs SPL |
| F-03 | UC-2.6.30, 31, 32, 33, 34, 35, 36, 38, 39, 40, 45, UC-5.3.23 | `match()` used as a search term, never matches | SPL |
| F-04 | UC-9.1.2, UC-4.1.2 | Manifest asserts a field the final `table` drops | manifest vs SPL |
| F-05 | UC-4.1.1 | SPL filters a value AWS does not emit; manifest disagrees | SPL |
| F-06 | UC-1.2.29 | Eval string `"\\"` is not a valid regex; Splunk rejects the search | SPL |
| F-07 | UC-2.6.44 | `match()` called with three arguments | SPL |
| F-08 | UC-3.2.1 | `earliest=-6h@5m` is not a valid time modifier | SPL |
| F-09 | UC-2.6.58, 62, 66, 68 | `timechart` with two split-by fields; Splunk rejects the search | SPL |
| F-10 | 64 fixtures in 13 groups | One generic event template reused for unrelated use cases | fixtures |
| F-11 | UC-5.1.1 | Fixture gives one qualifying group; manifest expects three rows | fixture vs SPL |

---

### F-01 UC-1.1.1 "Sustained Linux CPU Utilization Above 90 Percent"

* Symptom: `failed`, 0 rows for 3 `cpu` events; 2 field assertions fail.
* Evidence, without the add-on: each fixture event is one `top`-style table
  (`cpu pctUser pctNice ... pctIdle` header, then `all`, `cpu0`, ... rows). The SPL
  filters `cpu=all` and needs `cpu_load_percent`, which nothing derives without
  `Splunk_TA_nix` (its field extraction). Stage-by-stage row counts are 0 from the base
  search on.
* Evidence, with the add-on's fields emulated: a temporary
  `EVAL-cpu_load_percent = 100 - pctIdle` on sourcetype `cpu` and key=value events
  (`cpu=all pctIdle=2.34 pctUser=85.12`, three of them). The SPL then returns **1** row
  (`stats ... by observed_host`, then `where avg_cpu_percent>90`), not the 3 the manifest
  expects (`min_count: 3`). Its columns are `observed_host`, `sample_count`,
  `avg_cpu_percent`, ...; the manifest asserts `host` (values `linux-prod-01`) and
  `pctIdle` (`max: 10`), neither of which the search returns. Lab, 2026-11-24;
  the temporary props were removed afterwards.
* Conclusion: not a SUNavigator defect and not only a missing add-on. The manifest's
  `expected` block describes raw events, not the search's output.
* Suggested fix: `min_count: 1`; assert the search's own columns
  (`observed_host` values `["linux-prod-01"]`, `avg_cpu_percent` `min: 90`). Say in the
  notes which add-on fields the SPL depends on (`cpu_load_percent`).

### F-02 UC-1.1.8 "SSH Brute-Force Detection"

* Symptom: `failed`, 0 rows; `min_count: 5`; `src` must match `^(10|172|192)\.`.
* Evidence: all 7 events index and match (7 rows after the base search, `rex`, `where`
  and `bin`). `stats ... by _time src host` gives **one** row (src `10.99.0.42`,
  `attempts=7`), and `where attempts > 10` removes it. The fixture has fewer failures than
  the search's threshold, and one source can produce at most one row per 5-minute bin, so
  `min_count: 5` cannot be met by this data.
* Suggested fix: at least 11 failed-password events from one source inside one 5-minute
  window, and `min_count: 1`.

### F-03 `match()` as a search term (12 use cases)

* Use cases: UC-2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36, 2.6.38, 2.6.39,
  2.6.40, 2.6.45, UC-5.3.23.
* Example (UC-2.6.30): `index=xd (sourcetype="citrix:broker:events" event_type=Provisioning*
  OR match(_raw, "(?i)identity|prep|snapshot|MCS|Provision")) OR (...)`. UC-2.6.39 has
  `| search match(_raw, "...")`.
* Evidence: lab check on Splunk 10.2.9 with two events in the test index, one containing
  "identity": `<base> | where match(_raw, "(?i)identity|MCS")` returns 1 row;
  `<base> match(_raw, "(?i)identity|MCS")`, `<base> (match(...) OR event_type=Foo)` and
  `<base> | search match(...)` return 0. No error is shown. The term also removes the
  rest of its group: with JSON events carrying `"ODataEntity": "Machines"`,
  `ODataEntity=Machine*` returns 2 and `(ODataEntity=Machine* OR match(_raw, "(?i)drain"))`
  returns 0 (UC-2.6.34 has exactly that clause). The search silently matches nothing in
  production.
* In 11 of the 12, none of the fixture events would match the pattern either (see F-10),
  so both defects have to be fixed.
* Suggested fix: move the test into `| where match(_raw, "...")` (or use a wildcarded
  term), and give the fixture events that contain it.

### F-04 Manifest asserts a field the final `table` drops (UC-9.1.2, UC-4.1.2)

* UC-9.1.2: SPL ends `| table _time, Account_Name, CallerComputerName`; manifest asserts
  `EventCode` values `["4740"]`. Rows are returned (2 of 2) and the row count passes; the
  field assertion fails: the rows have only `_time` on the lab (the Windows add-on extracts
  `Account_Name`; `EventCode` is not in the table at all).
* UC-4.1.2: SPL ends `| table _time userIdentity.arn eventName sourceIPAddress awsRegion`;
  manifest asserts `userIdentity.type` values `["Root"]`. Rows are returned (2 of 2).
* Suggested fix: assert a column the search returns (`CallerComputerName`,
  `userIdentity.arn`), or add the field to `table`.

### F-05 UC-4.1.1 "Unauthorized API Calls"

* Symptom: 2 rows, `min_count: 3`.
* Evidence: the SPL selects `errorCode="AccessDenied" OR errorCode="UnauthorizedAccess"
  OR errorCode="Client.UnauthorizedAccess"`. The manifest lists
  `AccessDenied`, `UnauthorizedAccess` and `Client.UnauthorizedOperation`, and the third
  fixture event carries the last one. AWS emits `Client.UnauthorizedOperation`, so the SPL
  value is wrong and misses real events as well as the fixture. The final `table` also
  drops `errorCode`, which the manifest asserts.
* Suggested fix: `errorCode="Client.UnauthorizedOperation"` in the SPL; add `errorCode` to
  the `table` or assert another column.

### F-06 UC-1.2.29 "Registry Run Key Modification (Persistence)"

* Symptom: Splunk refuses the search: `Error in 'EvalCommand': Regex: \ at end of pattern`.
* Evidence: the SPL has `replace(TargetObject,"^.*\\","")`. In an eval string `\\` is one
  backslash, so the regex ends in a lone backslash. SUNavigator cannot deploy the search.
  *Correction (0.8.9):* the second call in the same search, `replace(TargetObject,"\\[^\\]+$","")`,
  was listed here as having the same defect. It does not: it unescapes to `\[^\]+$`, which is
  a valid regex, and Splunk accepts it (lab, 10.2.9). Only the `"^.*\\"` argument is wrong.
* *Addition (0.12.1, lint `L006`):* the same search has a second defect the report of 27 Nov 2026 did not list:
  `replace(registry_key_lc,"^\\registry\\user","hku")` unescapes to `^\registry\user`, and PCRE2 rejects `\u`
  (checked on 10.4.3 and on the parser: "PCRE2 does not support \F, \L, \l, \N{name}, \U, or \u"). UC-1.2.66 has the same
  class of defect in `"^.:\\users\\..."`. A fix of only the trailing backslash leaves both searches rejected.
* Suggested fix: `"^.*\\\\"` (a regex backslash needs four in an eval string). The search also filters on `source=`, which the control test cannot scope
  (see the last section).

### F-07 `match()` with three arguments (UC-2.6.44, UC-2.6.45)

* UC-2.6.44: `| where match(VolumeName, "Cache|WCD|MCS|WriteCache|PVS|Differencing", "i")
  OR 1=1`. Splunk: "The arguments to the 'match' function are invalid."; the search cannot
  be deployed. UC-2.6.45 has `match(_raw, "(power.?on|start|registration|boot)", "i")` too,
  but in a search clause (see F-03). *Correction (0.8.9):* Splunk **accepts** that search and
  never evaluates the call, so UC-2.6.45 is an F-03 case only, not an F-07 case; the lab
  parser rejects the three-argument call in `where` and `eval` only.
* Suggested fix: `match(x, "(?i)...")`. In UC-2.6.44 the `OR 1=1` makes the `where` keep
  everything; drop it or the `match`.

### F-08 UC-3.2.1 "Kubernetes pod restarts" (tstats)

* Symptom: Splunk refuses the search: `Error in 'TsidxStats': Invalid value "-6h@5m" for
  time term 'earliest'`.
* Evidence: `tstats ... WHERE ... earliest=-6h@5m latest=now ...`. A snap-to unit cannot
  carry a multiple.
* Suggested fix: `earliest=-6h@m` (or `-6h`), and bin to 5 minutes with `span=5m`.

### F-09 `timechart` with two split-by fields (UC-2.6.58, 2.6.62, 2.6.66, 2.6.68)

* Splunk refuses the search: `Error in 'timechart' command: The argument '<field>' is
  invalid.` The searches have `timechart span=1h count by reason, user_principal`,
  `... count by issue, store_name`, `... count by cat, plat`, `... count by action,
  outcome`. `timechart` takes one split-by field.
* Suggested fix: `bin _time span=1h | stats count by _time, reason, user_principal`, or
  combine the two fields into one before `timechart`.

### F-10 Generic fixtures reused across unrelated use cases (64 of 94 fixtures)

* Evidence: the first positive event of 64 fixtures is byte-identical, apart from
  `sourcetype` and `host`, to that of at least one other fixture. There are 13 such
  groups. Their searches filter on different terms, fields and values, so the events do
  not contain what the SPL needs (stage-by-stage counts show 0 rows at the base search or
  at the first `where`/`stats`). Of the 64, 41 fail for this reason alone, 16 also have an
  SPL defect (F-03 in 12, F-09 in 4), 3 cannot be scoped because they filter on `source=`,
  and 4 pass. Another 6 single fixtures (UC-2.6.42, 2.6.56, 2.6.57, 2.6.63, 2.6.78,
  2.6.79) are one-off placeholders of the same kind (`"msg": "synthetic Citrix ..."` and
  similar) that fail the same way.

| Fixtures | First event (start) | Use cases |
|---|---|---|
| 15 | `04/24/2026 08:15:00 AM EventType=LogonFailed MachineName=XD-VDA-00 UserName=jdoe ...` | UC-2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.35, 2.6.45, 2.6.47, 2.6.48, 2.6.49, 2.6.53, 2.6.75, UC-10.6.196, 10.6.197, 10.6.199, 10.6.200 |
| 11 | `Apr 24 08:15:00 citrix-lab-01 04/24/2026:08:15:00 GMT ... APPFW APPFW 123: CEF:0\|Citrix\|NetScaler...` | UC-5.3.23, 5.3.24, 5.3.25, 5.3.26, 5.3.27, 5.3.29, 5.3.32, 5.3.34, 5.3.35, 5.3.36, 5.3.37 |
| 5 | `04/24/2026 08:15:00 AM EventCode=1000 Source=Citrix ComputerName=citrix-lab-01 Message="Citrix service error: ...` | UC-2.6.38, 2.6.40, 2.6.41, 2.6.43, 2.6.54 |
| 5 | `{"_time": ..., "enrollment": "error", ...}` | UC-2.6.64, 2.6.65, 2.6.66, 2.6.68, 2.6.69 |
| 5 | `{"_time": ..., "actor": "u@ex.com", "action": "Download", "result": "fail", ...}` | UC-2.6.70, 2.6.71, 2.6.72, 2.6.73, 2.6.74 |
| 5 | `{"_time": ..., "site_id": "site-a", "path_name": "MPLS1", "loss_pct": 5.0, ...}` | UC-5.3.38, 5.3.39, 5.3.40, 5.3.41, 5.3.42 |
| 3 | `{"_time": ..., "ODataEntity": "Machines", ..."machine_name": "mcs-0", ...}` | UC-2.6.29, 2.6.34, 2.6.46 |
| 3 | `04/24/2026 08:15:00 AM EventType=ServiceRestart MachineName=XD-VDA-01 service=CtxCVdb ...` | UC-2.6.36, 2.6.39, 2.6.52 |
| 3 | `{"_time": ..., "user": "u1", "login_result": "fail", ...}` | UC-2.6.60, 2.6.62, 2.6.76 |
| 3 | `{"_time": ..., "appliance": "citrix-lab-01", "vserver": "vs-citrix-443", "rtt": 400, ...}` | UC-5.3.28, 5.3.30, 5.3.31 |
| 2 | `{"_time": ..., "user": "u1", "direction": "upload", "policy_result": "Block", ...}` | UC-2.6.61, UC-10.6.198 |
| 2 | `{"_time": ..., "proc_name": "winlogon", "unexpected_reboot": 1, ...}` | UC-2.6.37, 2.6.77 |
| 2 | `{"_time": ..., "risk_level": 80, ...}` | UC-2.6.58, 2.6.59 |

* Four fixtures pass only because of `coalesce` defaults (`unknown`, `Unknown`):
  UC-2.6.48, 2.6.55, 2.6.74, 2.6.76. A pass there says nothing about the data.
* Field names in some fixtures are not the ones the SPL reads: `EventType` against
  `event_type` (field names are case-sensitive), `machine_name` against `Name`,
  `ODataEntity` against `odata_resource`, `UserName` against `user`.
* Suggested fix: write the events of each fixture from the search's own filter terms and
  group-by fields (the ones named in its `stats ... by` and `where`), and set `min_count`
  to what the search's aggregation produces.

### F-11 UC-5.1.1 "Interface flapping"

* Symptom: 1 row, `min_count: 3`.
* Evidence: 7 events; the SPL ends `stats count by host, interface, state | where count > 3`
  and only `GigabitEthernet1/0/24` down (4 events) qualifies. The manifest expects 3 rows.
* Suggested fix: `min_count: 1`, or three interfaces with more than three events each.

---

### Not upstream defects (listed so they are not reported as such)

| UC | Verdict | Why |
|---|---|---|
| UC-5.2.3 | failed | `pan:threat` events are CSV; `severity`, `src`, `dest` come from `Splunk_TA_paloalto`, absent in the lab. Fails until the add-on is installed. |
| UC-1.2.4 | not_runnable | The SPL uses the lookup `windows_service_failure_policy.csv`, which the customer maintains; it does not exist on the lab. |
| UC-13.1.15 | not_runnable | Starts with `multisearch` over `_internal` and uses `tstats` and `inputlookup`; their data cannot be redirected to the test index. |
| UC-1.2.6, 2.6.28, 2.6.41, 2.6.43, 2.6.51, 2.6.54 | not_runnable | The SPL filters on `source=`; SUNavigator uses `source` as its per-run marker, so these cannot be scoped. A SUNavigator limitation, not Fenre's. |
| UC-10.2.1, UC-12.1.1 | passed (weak) | `timechart` returns empty buckets, which meet `min_count` without any data selected. Add assertions in the manifest. |

### What the lab showed about add-ons and `KV_MODE`

A second campaign run with `KV_MODE = json` on 38 sourcetypes gave the same verdict for
every fixture as the run without it: Splunk 10.2.9 extracts JSON events automatically
(`AUTO_KV_JSON`). The missing add-on matters only for key=value and CSV sourcetypes
(UC-1.1.1, UC-5.2.3, UC-9.1.2 columns), not for the JSON fixtures.
