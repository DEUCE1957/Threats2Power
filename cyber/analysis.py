import copy
from fractions import Fraction
import multiprocess as mp
from communication.network import CommNetwork
# TODO: Account for probability of 0 devices being compromised

def iterate_over_paths(path, prob, reachable_nodes={}, visited_nodes={}, id_to_node={}):
    current_id = path[-1]
    current_node = id_to_node[current_id]
    visited_previously = current_id in visited_nodes
    if not visited_previously:
        visited_nodes[current_id] = None
    
    neighbouring_nodes = {k.id:None for k in current_node.get_neighbours()}
    reachable_nodes.update(neighbouring_nodes)
    reachable_nodes = {k:None for k in reachable_nodes if k not in visited_nodes}
    success_prob = current_node.get_prob_to_compromise()
    # If we fail, this path terminates
    yield path, prob*(1-success_prob), True
    if visited_previously:
        return
    n_reachable = len(reachable_nodes)
    reachable_ids =  list(reachable_nodes.keys())
    for reachable_node_id in reachable_ids:
        yield from iterate_over_paths(path+[reachable_node_id], prob*success_prob*(1/n_reachable),
                                    copy.copy(reachable_nodes), copy.copy(visited_nodes),
                                    id_to_node=id_to_node)
        
    # No more nodes reachable (entire network compromised)
    if len(reachable_nodes) == 0:
        yield path, prob*success_prob, False

def get_all_paths(graph):
    n_nodes = len(graph.nodes())
    id_to_node = {node.id:node for node in graph.nodes()}
    start_ids = list(id_to_node.keys())
    # Different starting locations
    for start_node_id in start_ids:
        yield from iterate_over_paths([start_node_id], prob=1/n_nodes,
                                    reachable_nodes={}, visited_nodes={},
                                    id_to_node=id_to_node)

def static_analysis(network:CommNetwork, verbose:bool=True, show_paths:bool=False):
    """
    Add up the probability of compromising N devices for each possible path through the 
    network. Since the number of paths increases exponentially with network size, static
    analysis is only computationally tractable for small networks.
    Beware that since probabilities are between 0.0 and 1.0, longer paths can lead to
    floating point precision errors.

    Args:
        network (CommNetwork): A communication network with nodes and edges
        verbose (bool): Whether to print out summary information
        show_paths (bool): Whether to print out each path (can be very long for larger networks)
    """
    sum_probs = 0.0
    n_probs = {}
    for path_no, (path, prob, ends_on_failure) in enumerate(get_all_paths(network.graph)):
        if show_paths:
            print(f"Path {path_no} :: Prob {str(Fraction(prob).limit_denominator()):<15}" + 
                    f" :: {'-'.join([str(node) for node in path])} :: {ends_on_failure}")
        # if (len(path) > 1 and ends_on_failure) or (not ends_on_failure):
        path_length = len(path) - 1 if ends_on_failure else len(path)
        n_probs[path_length] = prob if path_length not in n_probs else n_probs[path_length] + prob
        sum_probs += prob
    if verbose:
        print(f"No. of Paths: {path_no}. Sum of Probabilities: {sum_probs} ({Fraction(sum_probs).limit_denominator()})")
    if verbose:
        print("\n".join(f"{k} devices: {v}" for k,v in sorted(n_probs.items(),key=lambda item: item[0])))
    return n_probs