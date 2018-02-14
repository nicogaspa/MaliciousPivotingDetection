import pivotingdetection as pivdet
import graphs
import loader
import parameters as par
import output
import time
start_time = time.time()


def main():
    """
    Main Function
    :return: None
    """
    start_time = time.time()
    flows = loader.load_flows(par.Year, par.Month, par.Day, par.HourStart, par.MinuteStart,
                              par.HourEnd, par.MinuteEnd)
    print "loaded "+str(len(flows))+" flows",
    print("--- %s seconds ---" % (time.time() - start_time))

    flows = loader.preprocess_dataf(flows)
    pivot_flows = loader.preprocess_for_pivots(flows)
    print "preprocessed "+str(len(flows))+" flows",
    print("--- %s seconds ---" % (time.time() - start_time))

    if not par.OnlyPivots:
        G_Complete = graphs.multidigraph_from_dataf(flows)
    G = graphs.multidigraph_from_dataf(pivot_flows)
    print "graph created",
    print("--- %s seconds ---" % (time.time() - start_time))

    nodes_pivots, edges_pivots = pivdet.detect_pivoting(G)
    print "pivot detection over, " + str(len(nodes_pivots)) + " pivots",
    print("--- %s seconds ---" % (time.time() - start_time))

    if par.OnlyPivots:
        risks_pivots = pivdet.find_malicious_pivoting(G, nodes_pivots, edges_pivots)
    else:
        risks_pivots = pivdet.find_malicious_pivoting(G_Complete, nodes_pivots, edges_pivots)
    print "malicious pivots detection over",
    print("--- %s seconds ---" % (time.time() - start_time))

    output.write_output("pivot_detection", G, nodes_pivots, edges_pivots, risks_pivots)
    if len(nodes_pivots) > 0:
        if par.OnlyPivots:
            graphs.draw_graph(G, nodes_pivots, edges_pivots)
        else:
            graphs.draw_graph(G_Complete, nodes_pivots, edges_pivots)

    print "End, ",
    print("--- %s seconds ---" % (time.time() - start_time))

    return None


if __name__ == "__main__":
    main()
