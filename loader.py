import pandas as pnd
import gzip
import sys
from netaddr import IPNetwork
import parameters as par
if sys.version_info[0] < 3:
    from StringIO import StringIO
else:
    from io import StringIO
pnd.options.mode.chained_assignment = None  # default='warn'


def load_flows(Y, M, D, hs, ms, he, me):
    """
    Function to load network flows from zipped NProbe output files into Pandas DataFrame
    :param Y: Year
    :param M: Month
    :param D: Day
    :param hs: Starting Hour
    :param ms: Starting Minute
    :param he: Ending Hour
    :param me: Ending Minute
    :return: Pandas DataFrame
    """

    if int(he) < int(hs):
        raise ValueError('Ending Hour must be greater or equal than Starting Hour')
    if (int(ms) < 0) | (int(ms) >= 60) | (int(me) < 0) | (int(me) >= 60):
        raise ValueError('Minutes valid values are from 0 to 59')
    if (int(hs) < 0) | (int(hs) >= 24) | (int(he) < 0) | (int(he) >= 24):
        raise ValueError('Hours valid values are from 0 to 23')

    data_list = []

    for h in range(int(hs), int(he)+1):
        maxmin = 60
        minmin = 0
        if str(h).zfill(2) == he:
            maxmin = int(me)+1
        if str(h).zfill(2) == hs:
            minmin = int(ms)

        for m in range(minmin, maxmin):
            with gzip.open("./Input/"+Y+"/"+M+"/"+D+"/"+str(h).zfill(2)+"/"+str(m).zfill(2)+".flows.gz", 'rb') as f:
                file_content = f.read()
                data_list.append(pnd.read_csv(StringIO(file_content), delimiter='|'))  # FASTER

    df = pnd.concat(data_list)
    df = df.reset_index(drop=True)

    return df


def preprocess_dataf(df):
    """
    Function to preprocess Pandas DataFrame and remove useless data
    Keeps only valid IPs
    :param df: Pandas DataFrame
    :return: Processed Pandas Dataframe
    """

    validips = []
    for cidr in par.ValidCIDR:
        validips.extend(str(ip) for ip in IPNetwork(cidr))

    df = df[df.IPV4_DST_ADDR.isin(validips)]
    df["OutLan"] = df.IPV4_DST_ADDR.str.slice(8, 10)

    if par.ConsiderExternal:
        df = df[df.IPV4_SRC_ADDR != "0.0.0.0"]
        df["FromOut"] = ~df.IPV4_SRC_ADDR.isin(validips)
        df["InLan"] = df.IPV4_SRC_ADDR.str.slice(8, 10)
        df.loc[df['FromOut'] == True, 'InLan'] = "-1"
    else:
        df = df[df.IPV4_SRC_ADDR.isin(validips)]
        df["InLan"] = df.IPV4_SRC_ADDR.str.slice(8, 10)
        df["FromOut"] = False

    # NOTES set time of flows from epoch to int
    df["FLOW_START_SEC"] = (df["FLOW_START_SEC"] * 1000000).astype(int)
    df["FLOW_END_SEC"] = (df["FLOW_END_SEC"] * 1000000).astype(int)

    df["Length"] = (df['FLOW_END_SEC'] - df['FLOW_START_SEC'])
    df["TotalRisk"] = 0

    df = df.reset_index(drop=True)

    return df


def preprocess_for_pivots(df):
    """
    Extra preprocessing operation to keep only candidate flows while checking for pivot activities
    :param df: Pandas DataFrame
    :return: Processed Pandas DataFrame
    """
    df = df[df.IN_BYTES > par.ByteMin]
    df = df[df.OUT_BYTES > par.ByteMin]

    df = df[df.Length >= par.FlowDurationMin]
    if par.FilterPorts:
        df = df[~df.L4_SRC_PORT.isin(par.filter_ports)]
        df = df[~df.L4_DST_PORT.isin(par.filter_ports)]

    return df
