#!/usr/bin/env python3
'''
aws security group audit script
'''
from sys import argv, exit as _e
from os import environ

from json import loads

DEBUG = environ['DEBUG'] if 'DEBUG' in environ else True
NOT_INTERESTED_PORT = [-1, 22, 80, 443, 8080] # -1 for ICMP
FROM_PORT_INDEX = 0

def debug_p(*args, **kwargs):
    '''
    debug print function
    '''
    if DEBUG:
        print(*args, **kwargs)


def parse_bounds(bounds):
    '''
    parse bound rules
    '''
    bound_list = []
    for bound in bounds:
        try:
            if '0.0.0.0' in str(bound['IpRanges']):
                _ = (bound['FromPort'], bound['ToPort'], bound['IpRanges'][0]['CidrIp'])
                bound_list.append(_)
        except KeyError:
            if '0.0.0.0' in str(bound['IpRanges']):
                bound_list.append(bound)

    return bound_list


try:
    FILE_NAME = argv[1]
except IndexError:
    print('Usage: ./parse_sg.py [filename]')
    _e(0)

with open(FILE_NAME, 'r') as f:
    JSON_SG = loads(f.read())

# TODO: add supporting for outbound rules `IpPermissionsEgress` # pylint: disable=W0511
for sg in JSON_SG['SecurityGroups']:
    desc = sg['Description']
    group_id = sg['GroupId']
    group_name = sg['GroupName']
    vpc_id = sg['VpcId']

    inbounds = sg['IpPermissions']

    count = 0
    inbound_list = parse_bounds(inbounds)

    if len(inbound_list) != 0:
        if group_name.startswith('launch'):
            continue

        is_vulnerable = False
        for inbound in inbound_list:
            try:
                if not inbound[FROM_PORT_INDEX] in NOT_INTERESTED_PORT:
                    is_vulnerable = True
            except KeyError:
                # if not specific port range is given, it accepts all ports.
                is_vulnerable = True

        if not is_vulnerable:
            continue

        debug_p(f'{group_name}({group_id}),{desc},{vpc_id}')
        for inbound in inbound_list:
            try:
                from_port, to_port, ip_ranges = inbound
                debug_p(f'{ip_ranges},{from_port},{to_port}')
            except ValueError:
                debug_p(inbound)
