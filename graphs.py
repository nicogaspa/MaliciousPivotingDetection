import matplotlib.pyplot as plt
import matplotlib.colors
import networkx as nx
import pandas as pnd
import parameters as par


def multidigraph_from_dataf(df):
    """

    Function to create a NetworkX MultiDiGraph given a Pandas Netflow dataframe
    :param df: Pandas dataframe
    :return: NetworkX MultiDiGraph
    """

    df = df.rename(columns={'FLOW_START_SEC': 'TimeStart', 'FLOW_END_SEC' : 'TimeEnd',
                            'IN_BYTES': 'InBytes', 'OUT_BYTES': 'OutBytes',
                            'IN_PKTS': 'InPkts', 'OUT_PKTS': 'OutPkts',
                            'L4_SRC_PORT': 'SrcPort', 'L4_DST_PORT': 'DstPort'})

    attr_list = ["TimeStart", "TimeEnd", "Length", "InBytes", "OutBytes", "InPkts", "OutPkts",
                 "SrcPort", "DstPort", "InLan", "OutLan", "TotalRisk"]

    gr = nx.from_pandas_dataframe(df, "IPV4_SRC_ADDR", "IPV4_DST_ADDR", attr_list, create_using=nx.MultiDiGraph())

    if par.ConsiderExternal:
        # NOTES set black nodes for outside the network
        node_colors = {el: 'black' for el in df[df["FromOut"] == True].IPV4_SRC_ADDR.unique()}
        node_colors.update({el: 'r' for el in
                            pnd.concat([df[df["FromOut"] == False]['IPV4_SRC_ADDR'],
                                        df['IPV4_DST_ADDR']]).unique()})
        nx.set_node_attributes(gr, "NodeColor", node_colors)
    else:
        node_colors = {}
        node_colors.update({el: 'r' for el in
                            pnd.concat([df['IPV4_SRC_ADDR'], df['IPV4_DST_ADDR']]).unique()})
        nx.set_node_attributes(gr, "NodeColor", node_colors)
    return gr


def draw_graph(gr, nodes_pivots, edges_pivots):
    """
    Function to draw the NetworkX Graph with marked pivots
    :param gr: NetworkX MultiDiGraph
    :param nodes_pivots: list of lists of pivot nodes
    :param edges_pivots: list of lists of pivot edges
    :return: None
    """

    # NOTES possible layouts
    # pos = nx.fruchterman_reingold_layout(gr)
    # pos = nx.shell_layout(gr)
    # pos = nx.spring_layout(gr, scale=20)
    pos = nx.random_layout(gr)

    plt.figure(figsize=(30, 30))
    cmap = plt.cm.rainbow
    norm = matplotlib.colors.Normalize(vmin=0, vmax=5)

    if not par.OnlyPivots:
        e = []
        drawn_edges = {}

        for edge in gr.edges(keys=True):
            if edge not in e:
                edge_data = gr.get_edge_data(edge[0], edge[1], key=edge[2])

                # NOTES If we have already drawn that connection
                if (edge[0], edge[1]) in drawn_edges:
                    old_edge_key = drawn_edges[(edge[0], edge[1])][0]
                    old_edge_val = drawn_edges[(edge[0], edge[1])][1]
                    # NOTES If the current TotalRisk is greater
                    if edge_data["TotalRisk"] > old_edge_val:
                        e.remove((edge[0], edge[1], old_edge_key))
                        drawn_edges[(edge[0], edge[1])] = [edge[2], edge_data["TotalRisk"]]
                        e.append(edge)
                else:
                    e.append(edge)
                    drawn_edges[(edge[0], edge[1])] = [edge[2], edge_data["TotalRisk"]]

        edge_colors = [cmap(norm(gr[u][v][k]["TotalRisk"])) for u, v, k in e]
        node_colors = [gr.node[u]["NodeColor"] for u in gr.nodes()]

        nx.draw_networkx(gr, pos, node_size=30, font_size=8, with_labels=True,
                         edge_color=edge_colors, node_color=node_colors, alpha=0.7,
                         font_weight="bold", edgelist=e)
    else:
        n = set()
        for nodes in nodes_pivots:
            for node in nodes:
                n.add(node)
        n = list(n)

        e = []
        drawn_edges = {}
        for edges in edges_pivots:
            for edge in edges:
                if edge not in e:
                    edge_data = gr.get_edge_data(edge[0], edge[1], key=edge[2])

                    # NOTES If we have already drawn that connection
                    if (edge[0], edge[1]) in drawn_edges:
                        old_edge_key = drawn_edges[(edge[0], edge[1])][0]
                        old_edge_val = drawn_edges[(edge[0], edge[1])][1]
                        # NOTES If the current TotalRisk is greater
                        if edge_data["TotalRisk"] > old_edge_val:
                            e.remove([edge[0], edge[1], old_edge_key])
                            drawn_edges[(edge[0], edge[1])] = [edge[2], edge_data["TotalRisk"]]
                            e.append(edge)
                    else:
                        e.append(edge)
                        drawn_edges[(edge[0], edge[1])] = [edge[2], edge_data["TotalRisk"]]

        node_colors = [gr.node[u]["NodeColor"] for u in n]
        edge_colors = [cmap(norm(gr[u][v][k]["TotalRisk"])) for u, v, k in e]

        nx.draw_networkx_nodes(gr, pos=pos, node_color=node_colors, alpha=0.9, node_size=30, nodelist=n)
        nx.draw_networkx_edges(gr, pos=pos, edge_color=edge_colors, edgelist=e, alpha=0.7)
        lab = {node: node for node in n}
        nx.draw_networkx_labels(gr, pos=pos, font_size=8, font_weight="bold", font_color='black',
                                labels=lab)

    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    plt.colorbar(sm)

    plt.axis('off')

    path_img = "./Output/GraphImages/plot_"\
               + str(par.Year).zfill(2) + str(par.Month).zfill(2) + str(par.Day).zfill(2) + "_" \
               + str(par.HourStart).zfill(2) + str(par.MinuteStart).zfill(2) \
               + str(par.HourEnd).zfill(2) + str(par.MinuteEnd).zfill(2) \
               + "E" + str(par.PropDelayMax) + ".svg"

    plt.savefig(path_img)
    plt.show()

    return None
