This assignment has been done to analyze two websites namely:
1. Google.com
2. Wits.ac.za

The analysis was done using network
tools namely: Wireshark, Traceroute, and curl. The
paper starts by analyzing various protocols which are
present on the application layer of the two websites.
After this, the transport layer security of the two websites is then analyzed. Finally, AS path analysis is performed to determine the internet paths from different
continents and countries to where these websites are
hosted.

The github repo can be found here: https://github.com/willie84/CSC5032Z--Assignment
Requirements: 

1. You need Ripe Atlas API Key
2. You need a MaxiMind Geolocation Account API key and the User Id. https://www.maxmind.com/en/home

The files present:
1. main.py is a python script with follwing 8 functions:
 
  1.1 send_ripe_measurement_request(domain, apikey): which send a 
      measurement request to the Ripe Atlas. https://atlas.ripe.net/
     You need an API Key and credits to run the measurements.
     The function performs a traceroute meaurement to 24 probes hosted in the 8 sources countries listed in the code. 
      
  1.2 fetch_ripe_result(result_id, output_file) function which fetches ripe results
     and save them in an output_file. The results are fetched after 20 minutes. 
     
  1.3 tracecdns(trace_data): which is a function that uses Maxmind geoloaction database to 
       determine the location of various probes. This is to analyze the path analysis
       taken by the internet traffic from probes to the detination./
       
  1.4 showTrafficPath(asntrace): This function prints the ASN Paths from different probes.
  
  1.5 executemeasurements(): is the function that call all the the other functions for internet measuremsnts operations.
      
  1.6 get_location(domain): returns the location of the server given a domain.
  
  1.7 get_records(domain): return the DNS records for various websites. The dns records tested are 
      ['A', 'AAAA', 'NS', 'MX', 'CNAME', 'TXT', 'SOA']
      
  1.8 gethttpheaders(domain): uses the python library return the HTTP headers for various websites.
  
2.The other files are results of running the above python script.

You can use either python 2 or python 3 to run the script. 
  