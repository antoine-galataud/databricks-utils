ACCESS_KEY = ""
SECRET_KEY = ""
REGION = ""
PORTS_TO_ADD = ["" , ""] #doesn't support ranges
PROTOCOLS_TO_ADD = ["tcp"]
DATABRICKS_SECURITY_GROUP = ''
CUSTOM_SECURITY_GROUP = ''

import boto.ec2

##
## get list of the IPAddresses to add
##
def get_databricks_instances():
  conn = boto.ec2.connect_to_region(REGION, 
                                    aws_access_key_id=ACCESS_KEY,    
                                    aws_secret_access_key=SECRET_KEY)
  
  group = conn.get_all_security_groups(filters={'group-name': DATABRICKS_SECURITY_GROUP})[0]
  instance_ids = [i.id for i in group.instances()]
  reservations = conn.get_all_instances(instance_ids)
  ip_addresses = [instance[0].ip_address for instance in [reservation.instances for reservation in reservations]]
  ip_addresses =  [ip + '/32' for ip in ip_addresses]
  return ip_addresses

##
## custom security group to which we add addresses
##
def get_datamining_security_group():
  conn = boto.ec2.connect_to_region(REGION, 
                                    aws_access_key_id=ACCESS_KEY,    
                                    aws_secret_access_key=SECRET_KEY)
  rs = conn.get_all_security_groups()  
  for r in rs:
    if (r.name.find(CUSTOM_SECURITY_GROUP) == 0):
      return r  
    
ip_addresses_to_add = get_databricks_instances()
datamining_security_group=get_datamining_security_group()

##
## forge security group rules
##
def existing_sec_group_rules(security_group):
  rules = []
  for rule in security_group.rules:
    for grant in rule.grants:
      rules.append({'ip':grant, 'proto': rule.ip_protocol, 'fp': rule.from_port, 'tp': rule.to_port})
  return rules

##
## Authorize: revoke existing rules and add new ones
##
existing_rules = existing_sec_group_rules(datamining_security_group)

for existing in existing_rules:
  datamining_security_group.revoke(ip_protocol=existing['proto'], 
                                  from_port=existing['fp'],
                                  to_port=existing['tp'],
                                  cidr_ip=existing['ip'])
                  
for ip_address in ip_addresses_to_add:
  for port in PORTS_TO_ADD:
     for protocol in PROTOCOLS_TO_ADD:
       datamining_security_group.authorize(ip_protocol=protocol, from_port=port, to_port=port, cidr_ip=ip_address)
        
##
## Print results
##
updated_datamining_security_group = get_datamining_security_group()
rule_matches = []
for rule in updated_datamining_security_group.rules:
  for ip_address in ip_addresses_to_add:
    for port in PORTS_TO_ADD:
      for protocol in PROTOCOLS_TO_ADD:
        if rule.ip_protocol == protocol and rule.from_port == port and rule.to_port == port: 
          rule_matches.append(rule)
for rule in rule_matches:
  for grant in rule.grants:
    print grant, rule 
