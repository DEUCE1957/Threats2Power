import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import colorsys
import networkx as nx
from tree import TreeNode
from comm_network import CommNetwork
from matplotlib.patches import Patch
from matplotlib import colors as mc

def lighten_color(color, amount=0.5):
    """
    Credit: Ian Hincks (https://stackoverflow.com/questions/37765197/darken-or-lighten-a-color-in-matplotlib)
    Lightens the given color by multiplying (1-luminosity) by the given amount.
    Input can be matplotlib color string, hex string, or RGB tuple.

    Examples:
    >> lighten_color('g', 0.3)
    >> lighten_color('#F034A3', 0.6)
    >> lighten_color((.3,.55,.1), 0.5)
    """

    try:
        c = mc.cnames[color]
    except:
        c = color
    c = colorsys.rgb_to_hls(*mc.to_rgb(c))
    return colorsys.hls_to_rgb(c[0], 1 - amount * (1 - c[1]), c[2])

def hierarchy_pos(G:nx.DiGraph, root:TreeNode, width:float=1., vert_gap:float=0.2, vert_loc:float=0, xcenter:float=0.5):

    '''
    Credit: Joel (https://stackoverflow.com/a/29597209/2966723) 
    Licensed under CC Attribution-Share Alike 
    
    
    If the graph is a tree this will return the positions to plot this in a 
    hierarchical layout.
    
    G (networkx.DiGraph): Graph (must be a tree)
    root (Node): Root node of current graph
    width (float): Horizontal space allocated for this branch - avoids overlap with other branches. Defaults to 1.0
    vert_gap (float): Gap between levels of hierarchy. Defaults to 0.2
    vert_loc (float): Vertical location of root. Defaults to 0.0
    xcenter (float): Horizontal location of root. Defaults to 0.5
    '''
    # if not nx.is_tree(G):
    #     raise TypeError('cannot use hierarchy_pos on a graph that is not a tree')

    if root is None:
        if isinstance(G, nx.DiGraph):
            root = next(iter(nx.topological_sort(G)))  #allows back compatibility with nx version 1.11
        else:
            root = np.random.choice(list(G.nodes))

    def _hierarchy_pos(G, root, width=1., vert_gap = 0.2, vert_loc = 0, xcenter = 0.5, pos = None, parent = None):
        '''
        see hierarchy_pos docstring for most arguments

        pos: a dict saying where all nodes go if they have been assigned
        parent: parent of this branch. - only affects it if non-directed

        '''
    
        if pos is None:
            pos = {root:(xcenter,vert_loc)}
        else:
            pos[root] = (xcenter, vert_loc)
        children = root.children # list(G.neighbors(root))
        if not isinstance(G, nx.DiGraph) and parent is not None:
            for child in children:
                child.remove_parents(parent)
        if len(children) !=0:
            dx = width/len(children)
            nextx = xcenter - width/2 - dx/2
            for child in sorted(children, key=lambda child:child.id):
                nextx += dx
                pos = _hierarchy_pos(G,child, width = dx, vert_gap = vert_gap, 
                                    vert_loc = vert_loc-vert_gap, xcenter=nextx,
                                    pos=pos, parent = root)
        return pos

            
    return _hierarchy_pos(G, root, width, vert_gap, vert_loc, xcenter)

def plot_communication_network(network:CommNetwork, palette:str="tab10", double:bool=False):
    """
    Plots a tree-like and spring layout of the given communication network.
    The visualization shows:
    * Entrypoints for possible cyberattacks
    * Different component types present in the network
    * Components that have been compromised

    Args:
        network (CommNetwork): A specific communication network
        palette (str, optional): Name of seaborn colour palette to use
        double (bool, optional): Whether to plot the communication network in both hierarchical
            and spring layout formats.
            Defaults to False.
    """
    node_color_mask = np.full(network.graph.number_of_nodes(), fill_value="#1f78b4", dtype=object)
    node_edge_color_mask = np.full(network.graph.number_of_nodes(), fill_value="#000000", dtype=object)
    edge_color_mask = np.full(network.graph.number_of_edges(), fill_value="#000000", dtype=object)

    # sns.color_palette("hls", 12)
    node_types = set(node.name for node in network.graph.nodes())
    color_lookup = {k:v for k,v in zip(node_types,
                        sns.color_palette(palette, n_colors=len(node_types)))}

    # Custom Legend
    legend_map = {}
    for i, node in enumerate(network.graph.nodes()):
        color = color_lookup[node.name]
        name = node.name
        # Lighten the color of nodes which are Entrypoints for potential cyberattacks
        if node.is_accessible:
            node_color_mask[i] = lighten_color(color, amount=0.6)
            name += " (entrypoint)"
        else:
            node_color_mask[i] = color

        if node.is_compromised:
            # Compromised/hacked nodes have a red outline around them
            node_edge_color_mask[i] = "#ff0000"
            name += " (compromised)"
        legend_map[name] = Patch(facecolor=node_color_mask[i],
                                      edgecolor=node_edge_color_mask[i])

    for j, (start_node, end_node) in enumerate(network.graph.edges()):
        # Edges / Communication Channels between 2 compromised nodes are compromised
        if start_node.is_compromised and end_node.is_compromised:
            edge_color_mask[j] = "#ff0000"

    # >> Plotting <<
    fig, axes = plt.subplots(nrows=1, ncols=2 if double else 1, 
                             figsize=(24 if double else 18,6), width_ratios=[0.6, 0.4] if double else [1.0])
    label_map = {node:node.id for node in network.graph.nodes()}
    labels, handles = zip(*sorted(zip(*(legend_map.keys(), legend_map.values())), key=lambda t: t[0]))

    # Hierarchical / Tree Visualization of Communication Network
    tree_pos = hierarchy_pos(nx.to_undirected(network.graph), network.root)
    ax = axes[0] if double else axes
    nx.draw_networkx_nodes(network.graph, pos=tree_pos, ax=ax,
                           node_size=400, node_shape="s", node_color=node_color_mask,
                           linewidths=1.0, edgecolors=node_edge_color_mask)
    nx.draw_networkx_labels(network.graph, pos=tree_pos, labels=label_map, ax=ax, font_size=10)
    nx.draw_networkx_edges(network.graph, pos=tree_pos, ax=ax, edge_color=edge_color_mask)
    
    
    # Spring Visualization of Communication Network
    if double:
        spring_pos = nx.layout.spring_layout(network.graph)
        ax = axes[1]
        nx.draw_networkx_nodes(network.graph, pos=spring_pos, ax=ax,
                            node_size=400, node_shape="s", node_color=node_color_mask, 
                            linewidths=1.0, edgecolors=node_edge_color_mask, )
        nx.draw_networkx_labels(network.graph, pos=spring_pos, labels=label_map, ax=ax, font_size=10)
        nx.draw_networkx_edges(network.graph, pos=spring_pos, ax=ax, edge_color=edge_color_mask)
    
    fig.legend(labels=labels, handles=handles, loc="lower center", bbox_to_anchor=(0.5, -0.1), ncol=len(labels),
               title="Legend", fancybox=True, fontsize='large', title_fontsize='larger')
    plt.tight_layout()
    plt.show()