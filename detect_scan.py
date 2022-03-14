import os
import sys
import time
from datetime import datetime
from collections import Counter

# Parse the lines and grab what is important
def get_lines(keyword):
	log_lines = []
	time_list = []
	with open("/var/log/messages", encoding="utf-8") as log:
		if os.stat("/var/log/messages").st_size < 10:
			return "Log is empty for now"
		for line in log:
			if keyword in line:
				l = line.split()
				source_ip = l[11][4:]
				# Initialise the time values
				year = datetime.today().year
				mon = int(0)
				day = int(0)
				hour = int(0)
				minute = int(0)
				seconds = int(0)

				# Parse the timestamp into month, day, hour, minute, second with ints.
				# Mar 13 03:53:35
				if "Jan" in l[0]:
					mon = 1
				elif "Feb" in l[0]:
					mon = 2
				elif "Mar" in l[0]:
					mon = 3
				elif "Apr" in l[0]:
					mon = 4
				
				# Parse the timestamp itself 
				day = int(l[1])
				hour = int(l[2][0:2])
				minute = int(l[2][3:5])
				second = int(l[2][6:8])

				# Make an epoch object of the datetime. 
				date_time_obj = datetime(year, mon, day, hour, minute, second).timestamp()
				
				# Pack the IP and timestamp as dicts then loop through them in a 5 minute loop. 
				time_list.append(date_time_obj)
				"""
				for i in range(len(time_list)):
					diff = time_list[i] - time_list[i-1]
					if diff < 0:
						continue
					print(diff)
				"""
				log_lines.append([source_ip, date_time_obj])
		
	return log_lines
		#for i in range(len(log_lines)):
		#	print(log_lines[i][1])
				

# Compares the two timestamps.
# https://stackoverflow.com/questions/4002598/how-to-get-the-previous-element-when-using-a-for-loop
def detect_and_block():
	# Counter of how many times an IP has appeared
	counter = 0
	# Primary list which logs the found IPs and try to attach the number of times they appeared in 5 minutes
	found_ips = []
	# IP addresses to be blocked
	block_ips = []
	# Times and IP address appearances
	get_times = get_lines("IPT")
	# Get a record of all IP addresses found making SYN connections
	for i in range(len(get_times)):
		found_ips.append(get_times[i][0])

	# Count the appearance of each IP address. 
	ip_count = Counter(found_ips)
	print(ip_count)
	# Access the number of packets tied to the IP as a dictionary.
	for ip_addr, pkt in ip_count.items():
		# If a value of higher than 100 is found
		if pkt >= 100:
			block_ips.append(ip_addr)
	
	# Quick check if the list to block IPs is empty then just exit early.
	if len(block_ips) == 0:
		sys.exit("There are no IP addresses to block right now.")
	
	for i in range(len(block_ips)):
		print("IP Address(es) to block: \n{}".format(block_ips[i]))
		# Place this rule above all other existing rules to block the IP trying to port scan.
		os.system("iptables -I INPUT -s {} -j DROP".format(block_ips[i]))
	
	
	# Temporary timer for which the blocking which will last.
	start_time = time.time()
	time_count = 120
	while (time.time() - start_time) < 120:
		time_count -= 1
		time.sleep(1)
		print("Unblocking in: {}".format(time_count))
	
	for i in range(len(block_ips)):
		print("Unblocking device... ")
		os.system("iptables -D INPUT -s {} -j DROP".format(found_ips[i]))
		#print("Restarting IPTables.")
		#os.system("systemctl restart iptables")
		
	print("Wiping log file")
	os.system("echo > /var/log/messages")



	#https://codefather.tech/blog/python-check-for-duplicates-in-list/
	#for i in range(len(get_times)):
		# Bind the apperance of the same IP address with a counter.
	"""
	for i in range(len(get_times)):
		counter += 1
		# Get the difference of time in which the SYN packet has came. 
		time_diff = get_times[i][1] - get_times[i-1][1]
		# Any minus values ignore.
		if time_diff < 0:
			continue
			
		if counter >= 50:
			found_ips.append(get_times[i][0])
			
		# Flush out the duplicates and block the offending IPs.
		found_ips = list(set(found_ips))
		#os.system("ipset create BlockAddress hash:ip hashsize 4096 2>/dev/null")
	
	for i in range(len(found_ips)):
		print("Offending IP to be blocked: {}".format(found_ips[i]))
		os.system("iptables -I INPUT -s {} -j DROP".format(found_ips[i]))
		#os.system("ipset add BlockAddress {} 2>/dev/null".format(found_ips[i]))
	
	#os.system("iptables -t raw -A PREROUTING -m set --match-set BlockAddress src -j DROP")

	if len(found_ips) == 0:
		print("I found nothing for now, flushing previous ruleset.")
		os.system("ipset -F")
		return 0

	start_time = time.time()
	time_count = 120
	while (time.time() - start_time) < 120:
		time_count -= 1
		time.sleep(1)
		print("Unblocking in: {}".format(time_count))

	for i in range(len(found_ips)):
		print("Deleting IPTables rules.")
		os.system("iptables -D INPUT -s {} -j DROP".format(found_ips[i]))
		print("Restarting IPTables.")
		os.system("systemctl restart iptables")
		print("Wiping log.")
		os.system("echo > /var/log/messages")
	"""

# Using datetime objects we do calculations.
#new_timestamp = str(datetime.utcfromtimestamp(timestamp).strftime("%b %d %H:%M:%S.%f"))
#test = datetime.strptime(new_timestamp, "%Y-%m-%d %H:%M:%S.%f")

# Individually grab each timestamp
#get_line = get_lines("IPT")

detect_and_block()

"""
def get_details():
	time_list = []
	log_lines = get_lines("IPT")
	prev_line = ''
	for log_line in log_lines:
		print("Current line: ", log_line)
		timestamp = str(log_line[0]) + ' ' + str(log_line[1]) + ' ' + str(log_line[2])
		source_ip = log_line[11][4:]
		print(timestamp, source_ip)
"""

#get_details = get_details()

"""
get_line = get_line("IPT")
print(get_line)

timestamp = str(get_line[0]) + ' ' + str(get_line[1]) + ' ' + str(get_line[2])
print(timestamp)

num_days = compare_timestamps(timestamp, 'Jan 27 11:52:02'
"""
