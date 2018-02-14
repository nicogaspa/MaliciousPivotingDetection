import parameters as par
import json


def rec_find(gr, previous_caller, edges, n_caller, last_time, nodes_pivots, edges_pivots):
    """
    Recursive function to analyze all of the edges from a node and mark pivots.
    It uses parameters from the "parameters.py" file.
    :param gr: NetworkX MultiDiGraph
    :param previous_caller: List of previously passed through nodes
    :param edges: List of previously passed through edges
    :param n_caller: previous node
    :param last_time: finishing time of last network flow
    :param nodes_pivots: list of all of the pivot nodes found, to return
    :param edges_pivots: list of all of the pivot edges found, to return
    :return: None
    """

    flag = 0  # NOTES To signal if another recursion has been called or not

    if len(previous_caller) == par.PivotLengthMax:
        nodes_pivots.append(list(previous_caller))
        edges_pivots.append(list(edges))
        return None

    for edge in gr.edges_iter(n_caller, data=True, keys=True):
        # NOTES necessary for first edge, since we don't have a starting time
        if last_time == 0:
            prop_delay = 0
        else:
            prop_delay = edge[3]["TimeStart"] - last_time

        # NOTES not coming back, not before the previous, respecting PropDelay
        if (edge[1] not in previous_caller) \
                & (prop_delay <= par.PropDelayMax)\
                & (edge[3]["TimeStart"] >= last_time):

            flag = 1
            previous_caller.append(edge[1])
            edges.append(list([edge[0], edge[1], edge[2]]))
            rec_find(gr, previous_caller, edges, edge[1], edge[3]["TimeStart"],
                     nodes_pivots, edges_pivots)

            # NOTES remove current edge from previous caller in order to keep valid multiple edges
            # NOTES between same nodes
            previous_caller.remove(edge[1])
            edges.remove(list([edge[0], edge[1], edge[2]]))

    if (flag == 0) \
            & (len(previous_caller) >= par.PivotLengthMin) \
            & (len(previous_caller) <= par.PivotLengthMax):
        nodes_pivots.append(list(previous_caller))
        edges_pivots.append(list(edges))

    return None


def detect_pivoting(gr):
    """
    Function to detect and mark pivoting activities in a NetworkX MultiDiGraph
    :param gr: initialized NetworkX MultiDiGraph
    :return nodes_pivots: list of lists of pivot nodes
    :return edges_pivots: list of lists of pivot edges
    """
    nodes_pivots = []
    edges_pivots = []
    last_time = 0

    for n in gr.nodes_iter():
        previous_caller = [n]
        edges = []
        rec_find(gr, previous_caller, edges, n, last_time, nodes_pivots, edges_pivots)

    return nodes_pivots, edges_pivots


def read_malicious_json(filename):
    """
    Reads the json file
    :return: python dictionary
    """
    json_data = open(filename).read()
    malicious_data = json.loads(json_data)
    return malicious_data


def find_malicious_pivoting(gr, nodes_pivots, edges_pivots):
    """
    Function to find and mark all of the suspicious pivots
    given the graph and the list of pivots found
    :param gr: NetworkX MultiDiGraph
    :param nodes_pivots: list of lists of pivot nodes
    :param edges_pivots: list of lists of pivot edges
    :return: list of lists of risk values for each pivot
    """

    risks_pivots = []

    malicious_data = read_malicious_json(par.maliciousIPs_filename)

    for nodes, edges in zip(nodes_pivots, edges_pivots):
        # NOTES Risk Values
        n_risk = 0  # Path novelty
        r_risk = 0  # Reconnaissance
        z_risk = 0  # LAN involved
        s_risk = 0  # Ports involved
        e_risk = 0  # Anomalous Data Transfer
        length = len(nodes)
        lan_crossed = set()

        for i, edge in enumerate(edges):
            edge_data = gr.get_edge_data(edge[0], edge[1], key=edge[2])

            # TODO check novelty

            if i == 0:
                lan_crossed.add(edge_data['InLan'])
                if edge[0] in malicious_data["AnomalousDataTransfer"]:
                    e_risk = 1

            lan_crossed.add(edge_data['OutLan'])

            if (edge_data['SrcPort'] not in par.norm_ports) & (edge_data['DstPort'] not in par.norm_ports):
                s_risk = s_risk + 1

            if edge[1] in malicious_data["AnomalousDataTransfer"]:
                e_risk = 1
            if edge[0] in malicious_data["Reconnaissance"]["Sending"]:
                r_risk = r_risk + 1

        r_risk = float(r_risk) / length
        z_risk = float(len(lan_crossed)) / length
        s_risk = float(s_risk) / (length-1)

        total_risk = n_risk + r_risk + z_risk + s_risk + e_risk

        risks_pivots.append([n_risk, r_risk, z_risk, s_risk, e_risk, total_risk])

        # NOTES setting same (maximum) risk value for all of the pivoting flows
        for edge in edges:
            edge_data = gr.get_edge_data(edge[0], edge[1], key=edge[2])
            if edge_data['TotalRisk'] < total_risk:
                edge_data['TotalRisk'] = total_risk

    return risks_pivots
