#!/usr/bin/env python

################################################################################
# Author: Vijay Thakorlal
# Date: January 12, 2016
# File name: summarise_azure_ips.py
# Version: 0.0.1
# Purpose: Retrieves the Azure IP ranges and calculates subnet ranges to be used
# in whitelisting Azure IPs in Azure Network Security Group rules.
#
#
################################################################################


################################################################################
# Import Modules
################################################################################
import sys

# OptionParse is deprecated since Python 2.7 so we'll use argparse
import argparse

import logging

import bs4
import requests
import lxml.etree
import ipaddress, netaddr
import xml.etree.ElementTree as ET

################################################################################
# Global Variables
################################################################################

#This probably shouldn't be hard coded
AZURE_IP_RANGES_URL='https://www.microsoft.com/EN-US/DOWNLOAD/confirmation.aspx?id=41653'
REGIONS_XPATH = '/AzurePublicIpAddresses/Region'
REGION_LIST_FILE='region_list.txt'
CURRENT_AZURE_IP_LIST_FILE='current-public-ips.xml'
LOG = logging.getLogger(__name__)


################################################################################
# Argument Parser
################################################################################

help_epilog = ("Here is an example command:\n"
" python summarise_azure_ips.py --region northeurope"
)


parser = argparse.ArgumentParser(description='Azure IP Range Summarisation Tool',epilog=help_epilog)
parser.add_argument('--region', required=True, help='The name of the Azure regions for which to summarise IPs e.g. northeurope')
parser.add_argument('--ip_range_file_url', required=False, help='The URL from where the Azure Public IP range XML file can be downloaded')

################################################################################
# Parse the arguments
################################################################################

args = parser.parse_args()
target_region = args.region
if args.ip_range_file_url:
	AZURE_IP_RANGES_URL = args.ip_range_file_url

################################################################################
# Functions
################################################################################

def parse_regions(ip_range_filename,region_list_filename):
    rtree = lxml.etree.parse(ip_range_filename)
    regions = rtree.xpath(REGIONS_XPATH)

    region_list_file = open(region_list_filename, 'w')

    for r in regions:
        region_name = r.get('Name')
        print('Extracting region: %s') %  region_name
        line = region_name + "\n"
        region_list_file.write(line)

    region_list_file.close()


def download_ip_ranges(ip_range_filename):
    r = requests.get(AZURE_IP_RANGES_URL)
    html_soup = bs4.BeautifulSoup(r.content, "lxml")
    a = html_soup.find('a', class_='failoverLink')

    #print("Debug: Azure IP Range Download Page - Links: %s") % a

    rkwargs = dict(
        stream=True,
        verify=False,
        timeout=20
    )

    r2 = requests.get(
        a['href'],
        **rkwargs
    )

    #print("Debug: Azure IP Range XML: %s") % r2.content

    with open(ip_range_filename,'wb') as f:
        f.write(r2.content)
        f.close()

def getRegionIps(xml, regionName):
    ipRanges = []
    for index, child in enumerate(xml):
        if child.attrib['Name'] == regionName:
            for element in child:
                if element.tag == 'IpRange':
                    ipRanges.append(element.attrib['Subnet'])
            return ipRanges

def summarizeCidrs(ranges):
    ipList = []
    for network in ranges:
        cidr = netaddr.IPNetwork(network)
        cidr.prefixlen = 19
        ipList.append(cidr)
    return netaddr.cidr_merge(ipList)

################################################################################
# Main program
################################################################################

def main():
    print("Downloading Azure IP ranges from %s") % AZURE_IP_RANGES_URL
    download_ip_ranges(CURRENT_AZURE_IP_LIST_FILE)
    parse_regions(CURRENT_AZURE_IP_LIST_FILE,REGION_LIST_FILE)

    # Add validation that the region name is listed in the file
    file_obj = open(REGION_LIST_FILE,'r')
    VALID_REGIONS = file_obj.read().splitlines()
    file_obj.close()

    if target_region not in VALID_REGIONS:
        print("Error the specified region, %s, is not a valid region") % target_region
        print("VALID AZURE REGIONS: %s") % VALID_REGIONS
        sys.exit(1)

    root = ET.parse(CURRENT_AZURE_IP_LIST_FILE).getroot()

    # find the right Azure Region IPs
    #ranges = getRegionIps(root, 'europewest')
    ranges = getRegionIps(root, target_region)
    print ranges

    summarised = summarizeCidrs(ranges)
    print("Length before summarisation: ", len(ranges))
    print("Length after summarisation: ", len(summarised))

    moreSummarised = netaddr.cidr_merge(summarised)
    print("Length after more summarisation: ", len(moreSummarised))



################################################################################
# Program Execution
################################################################################

if __name__ == "__main__":
    main()

