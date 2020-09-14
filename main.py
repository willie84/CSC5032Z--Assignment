import ssl
import dns
import dns.resolver
import sys, getopt
import json
import geoip2.webservice
import geoip2.database
import requests
import time
import subprocess
from pprint import pprint
from datetime import datetime
from ripe.atlas.cousteau import (
    Ping,
    Traceroute,
    AtlasSource,
    AtlasCreateRequest,
    AtlasResultsRequest
)

pathToDb = "GeoLite2-City.mmdb"
pathToAsnDb = "GeoLite2-ASN.mmdb"

#some code adopted from RIPE Atlas cousteau tutorial. https://github.com/RIPE-NCC/ripe-atlas-cousteau
def send_ripe_measurement_request(domain, apikey):
    traceroute1 = Traceroute(
        af=4,
        target=domain,
        description="testing",
        protocol="ICMP",
    )

    vantage1 = AtlasSource(
        type="country",
        value="KE",
        requested=3,
        tags={"include": ["system-ipv4-works"]}
    )

    vantage2 = AtlasSource(
        type="country",
        value="SN",  # , SENEGAL],
        requested=3,
        tags={"include": ["system-ipv4-works"]}
    )

    vantage3 = AtlasSource(
        type="country",
        value="CA",  # , CANADA],
        requested=3,
        tags={"include": ["system-ipv4-works"]}
    )

    vantage4 = AtlasSource(
        type="country",
        value="GB",  # , UNITED KINGDOM],
        requested=3,
        tags={"include": ["system-ipv4-works"]}
    )

    vantage5 = AtlasSource(
        type="country",
        value="US",  # , USA],
        requested=3,
        tags={"include": ["system-ipv4-works"]}
    )
    vantage6 = AtlasSource(
        type="country",
        value="BR",  # , Brazil "CA", "PL", "AU", "AR"],
        requested=3,
        tags={"include": ["system-ipv4-works"]}
    )
    vantage7 = AtlasSource(
        type="country",
        value="RU",  # , RUSSIA
        requested=3,
        tags={"include": ["system-ipv4-works"]}
    )
    vantage8 = AtlasSource(
        type="country",
        value="CN",  # , CHINA
        requested=3,
        tags={"include": ["system-ipv4-works"]}
    )

    atlas_request = AtlasCreateRequest(
        start_time=datetime.utcnow(),
        key=apikey,
        measurements=[traceroute1],
        sources=[vantage1, vantage2, vantage3, vantage4, vantage5, vantage6, vantage7, vantage8],
        is_oneoff=True
    )

    is_success, response = atlas_request.create()
    result_id = []
    if is_success:
        result_id = response['measurements']
        print(result_id)
        return result_id
    else:
        print("Measurement request was not successful")
        return []


def fetch_ripe_result(result_id, output_file):
    # fetch the result
    kwargs = {
        "msm_id": result_id,
    }

    # while not_fetched:
    is_success, results = AtlasResultsRequest(**kwargs).create()
    if is_success:
        probenumber = 1
        print(len(results))
        for res in results:
            print(probenumber, ":vantage address: ", res['src_addr'])
            probenumber += 1
        with open(output_file, 'w') as outfile:
            json.dump(results, outfile)


def tracecdns(trace_data):
    filename = trace_data
    asn_path = []
    with geoip2.database.Reader(pathToDb) as reader:
        with geoip2.database.Reader(pathToAsnDb) as asn_reader:
            with open(filename) as json_file:
                data = json.load(json_file)
                probenumber = 1
                for result in data:
                    try:
                        asn_response = asn_reader.asn(result['src_addr'])
                        asn = asn_response.autonomous_system_number
                        asn_path.append(str(asn))
                    except:
                        asn = "vantage ASN unknown"
                        asn_path.append(asn)
                    print("Result number", probenumber, "from address", result['src_addr'], "from ASN", asn)
                    probenumber += 1
                    for tracert in result['result']:

                        if tracert['result'][1] != {"x": "*"}:
                            hop_ip = tracert['result'][1]['from']
                            # geolocate the ip
                            try:
                                asn_response = asn_reader.asn(hop_ip)
                                response = reader.city(hop_ip)
                                asn = asn_response.autonomous_system_number
                                asn_path.append("->" + str(asn))
                                city = response.city.name
                                print(hop_ip, city, asn)
                            except:
                                print("IP not in the ASN database")
                    print("ASN path taken from address", result['src_addr'], "to destination:")
                    showTrafficPath(list(dict.fromkeys(asn_path)))
                    asn_path.clear()
                    print("")


def showTrafficPath(asntrace):
    for asn in asntrace:
        print(asn, end="")
    print('\n')


def executemeasurements():
    a = 'www.google.com'
    wits = 'www.wits.ac.za'
    apikey = "eb6310a8-2bb2-487d-a277-dd32e6c5256b"

    googleresultid = send_ripe_measurement_request(a, apikey)
    witsresultsid = send_ripe_measurement_request(wits, apikey)
    print("Wait 20 minutes to get results from RIPE...")
    time.sleep(1200)
    if len(googleresultid) != 0:
        fetch_ripe_result(googleresultid[0], "google_trace.txt")
    else:
        print("Results for", a, "could not be fetched")

    if len(witsresultsid) != 0:
        fetch_ripe_result(witsresultsid[0], "wits_trace.txt")
    else:
        print("Results for", wits, "could not be fetched")

    tracecdns("google_trace.txt")
    tracecdns("wits_trace.txt")


def get_location(domain):
    answers = dns.resolver.query(domain, 'A')
    for rdata in answers:
        ip = rdata.to_text()
    print("The IPv4 of this website is ", domain, ip)
    with geoip2.webservice.Client(393383, 'kmt9mF2RPrwP5I7A') as client:
        response = client.insights(ip)
        print("The Location where hosting of this website: Latitude", domain, response.location.longitude,
              "Longitude: ", response.location.latitude)
        print("The city of this website server", domain, response.city.name)
        print("The country name where the server of this", domain, response.country.name)


def get_records(domain):
    """
    Get all the records associated to domain parameter.
    :param domain: 
    :return: 
    """
    idzs = ['A', 'AAAA', 'NS', 'MX', 'CNAME', 'TXT', 'SOA']
    print("The Website being tested is: ", domain)
    for a in idzs:
        try:
            answers = dns.resolver.query(domain, a)

            for rdata in answers:
                print("The DNS Record: ", a, ':', rdata.to_text())

        except Exception as e:
            print(e)  # or pass


def gethttpheaders(domain):
    r = requests.get(domain)
    print("Headers for this Domain: ", domain, r.headers.keys())
    print("The request performed is: ", r.request.headers)
    print("The cookies available for this domain: ", domain, r.cookies)


# Testing the functions
a = 'https://www.google.com'
b = 'https://www.wits.ac.za'
get_records('google.com')
cname = dns.resolver.query('analytics.google.com', 'CNAME')
for rdata in cname:
    print("The canonical name of the analytics.google.com is", rdata.to_text())
print(" ")
print(" ")
get_records('wits.ac.za')
cname = dns.resolver.query('ftp.wits.ac.za', 'CNAME')
for rdata in cname:
    print("The canonical name of the ftp.wits.ac.za is", rdata.to_text())

print(" ")
print(" ")
get_location('google.com')
get_location('wits.ac.za')
print(" ")
print(" ")
gethttpheaders(a)
gethttpheaders(b)
executemeasurements()
