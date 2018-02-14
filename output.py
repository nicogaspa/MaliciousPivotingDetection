import json
import parameters as par


def write_output(filename, gr, nodes_pivots, edges_pivots, risks_pivots):
    """
    Function to write all of the pivots found in the NetworkX Graph in a JSON file
    :param filename: filename where to save the output
    :param gr: NetworkX MultiDiGraph
    :param nodes_pivots: list of lists of pivot nodes
    :param edges_pivots: list of lists of pivot edges
    :param risks_pivots: list of lists of pivot risk values
    :return: None
    """
    # ./Output/filename_YYYYMMDD_HHmmHHmm_EPropDelay.json
    file_path = "./Output/"+filename+"_"\
                + str(par.Year).zfill(2)+str(par.Month).zfill(2)+str(par.Day).zfill(2)+"_"\
                + str(par.HourStart).zfill(2)+str(par.MinuteStart).zfill(2)\
                + str(par.HourEnd).zfill(2)+str(par.MinuteEnd).zfill(2)\
                + "E"+str(par.PropDelayMax)+".json"

    f = open(file_path, 'w')
    i = 0  # NOTES Counter, to write

    pivotdict = {}
    for nodes, edges, risks in zip(nodes_pivots, edges_pivots, risks_pivots):
        in_bytes = []
        in_pkts = []
        out_bytes = []
        out_pkts = []
        time_flows = []
        time_end_flows = []
        len_flows = []
        src_ports = []
        dst_ports = []

        for edge in edges:
            edge_data = gr.get_edge_data(edge[0], edge[1], key=edge[2])
            in_bytes.append(edge_data["InBytes"])
            in_pkts.append(edge_data["InPkts"])
            out_bytes.append(edge_data["OutBytes"])
            out_pkts.append(edge_data["OutPkts"])
            time_flows.append(edge_data["TimeStart"])
            time_end_flows.append(edge_data["TimeEnd"])
            len_flows.append(edge_data["Length"])
            src_ports.append(edge_data["SrcPort"])
            dst_ports.append(edge_data["DstPort"])

        pivot = {}
        pivot["IP_nodes"] = nodes
        pivot["Bytes_Input"] = in_bytes
        pivot["Pkts_Input"] = in_pkts
        pivot["Bytes_Output"] = out_bytes
        pivot["Pkts_Output"] = out_pkts
        pivot["Time_Flows"] = time_flows
        pivot["Time_End_Flows"] = time_end_flows
        pivot["Time_Length_Flows"] = len_flows
        pivot["Ports_Src"] = src_ports
        pivot["Ports_Dst"] = dst_ports
        # pivot["Epsilon"] = time_flows[1]-time_flows[0]
        pivot["Risk_PathNovelty"] = risks[0]
        pivot["Risk_Reconnaissance"] = risks[1]
        pivot["Risk_LANs"] = risks[2]
        pivot["Risk_Ports"] = risks[3]
        pivot["Risk_Anomalous_Data"] = risks[4]
        pivot["Risk_Total"] = risks[5]

        pivotdict[i] = pivot
        i = i+1

    f.write(json.dumps(pivotdict, sort_keys=True, indent=4, separators=(',', ': ')))

    return None
