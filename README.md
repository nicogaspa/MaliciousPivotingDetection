# MaliciousPivotingDetection

Python application to detect and analyze pivoting activities given network flows from NProbe.
It relies on the following IEEE paper:  http://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8078189&tag=1

The application takes as input:
parameters.py, configuration file
MaliciousIP.json, list of malicious IP suspected of reconnaissance activities or anomalous data transfer.
Input, folder with Nprobe data, linked in folders by /Year/Month/Day/Hours/minutes.tar.gz

The application creates as output:
GraphImages, every graph image created, vector image
JSON outputs, containing json data

Configuration:
ValidCIDR, list of valid CIDR, subnet considered
ConsiderExternal, True if we want to consider also flows coming from IPs outside the valid CIDR
norm_ports, ports whitelist
maliciousIP_filename, filename of JSON input file
OnlyPivots, True to show only pivoting activities or False to show every flow.
filter_ports, ports to filter 
FilterPorts, True if we eant to filter the previous configuration value ports.
ByteMin, minimum byte exchange to consider flow part of pivoting activities
PivotLengthMin & PivotLengthMax, nodes involved to consider pivoting activities
FlowDurationMin, minimum duration to consider flow part of pivoting activities
Year, Month, Day, HourStart, MinuteStart, HourEnd, MinuteEnd, to specify time interval to check
