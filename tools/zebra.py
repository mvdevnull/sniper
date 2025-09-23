import requests

input_file = "zebra.txt"
output_file_finding = "finding.zebra.txt"
output_file_nofinding = "no.finding.zebra.txt"

# The data for the POST request
payload = {"0": "1234"}
# The timeout value in seconds, as specified in the curl command. 
# It is a tuple to separately define the connect and read timeouts, but a single integer value works for both as well.
timeout_seconds = 5

with open(input_file, "r") as infile, \
     open(output_file_finding, "w") as outfile_finding, \
     open(output_file_nofinding, "w") as outfile_nofinding:
    
    for line in infile:
        ip = line.strip()
        if not ip:
            continue
        
        url = f"http://{ip}/authorize"
        
        try:
            # Send the POST request using the requests library
            response = requests.post(url, data=payload, timeout=timeout_seconds)
            
            # Check for the "Access Granted" string in the response text
            if "Access Granted" in response.text:
                print(f"[+] Access Granted for {ip}")
                outfile_finding.write(ip + "\n")
            else:
                print(f"[-] Access Denied for {ip}")
                outfile_nofinding.write(ip + "\n")
        
        except requests.exceptions.Timeout:
            # Handle the timeout error
            print(f"[!] Timeout error contacting {ip}")
        except requests.exceptions.ConnectionError as e:
            # Handle other connection-related errors
            print(f"[!] Connection error contacting {ip}: {e}")
        except requests.exceptions.RequestException as e:
            # Handle any other requests-related exceptions
            print(f"[!] An unexpected error occurred with {ip}: {e}")
