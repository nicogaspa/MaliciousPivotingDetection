# Time to check
Year = "2017"
Month = "06"
Day = "12"  # "02"
HourStart = "00"
MinuteStart = "00"
HourEnd = "12"
MinuteEnd = "00"

# Valid IP CIDRs
ValidCIDR = ["185.156.48.0/21", "185.156.56.0/23"]

# Pivoting parameters
FlowDurationMin = 20000000
PropDelayMax = 1000000  # 1000000 = 1sec
PivotLengthMax = 6
PivotLengthMin = 3
ByteMin = 0

# Consider pivots that starts from an external node
ConsiderExternal = True
# Filter unwanted post from list
FilterPorts = True
# Show only pivoting flows
OnlyPivots = True

filter_ports = [0, 1, 6, 7, 67, 139, 137, 135, 151, 199, 427, 444, 445, 514,
                515, 548, 631, 691, 783, 1900, 2869, 3702, 5000, 5060, 5223,
                5353, 5355, 5357, 6771, 6881, 9100, 17500]
norm_ports = [22, 23, 443, 3389, 5938]  # 22 SSH,23 Telnet,443 SSLH Multiplexing,3389 Windows Remote,5938 Team Viewer

maliciousIPs_filename = "MaliciousIP.json"