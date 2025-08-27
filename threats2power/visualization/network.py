import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import colorsys
import networkx as nx
from pathlib import Path
from matplotlib.patches import Patch
from matplotlib import colors as mc
from matplotlib.axis import Axis
from ..communication.graph import CommNode
from ..communication.network import CommNetwork
from ..attackers.interface import Attacker


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

def hierarchy_layout(G:nx.DiGraph, root:CommNode, size:float=1., gap:float=0.2, loc:float=0, center:float=0.5, invert:bool=True):

    '''
    Credit: Joel (https://stackoverflow.com/a/29597209/2966723) 
    Licensed under CC Attribution-Share Alike 
    
    
    If the graph is a tree this will return the positions to plot this in a 
    hierarchical layout.
    
    G (networkx.DiGraph): Graph (must be a tree)
    root (Node): Root node of current graph
    size (float): Space allocated for this branch - avoids overlap with other branches. Defaults to 1.0
    gap (float): Gap between levels of hierarchy. Defaults to 0.2
    loc (float): Location of root. Defaults to 0.0
    center (float): Location of root. Defaults to 0.5
    invert (bool): If False, horizontal orientation is assumed (i.e. center is x position, loc is y position) otherwise vertical.
    '''
    if root is None:
        if isinstance(G, nx.DiGraph):
            root = next(iter(nx.topological_sort(G)))  #allows back compatibility with nx version 1.11
        else:
            root = np.random.choice(list(G.nodes))

    def _hierarchy_pos(G, root, size=1., gap=0.2, loc=0, center=0.5, pos={}, parent=None, invert=False):
        '''
        see hierarchy_pos docstring for most arguments

        pos: a dict saying where all nodes go if they have been assigned
        parent: parent of this branch. - only affects it if non-directed

        '''
        pos[root] =  (loc, center) if invert else (center,loc) 
        
        # Select Children of this Node
        children = root.children # list(G.neighbors(root))  
              
        if not isinstance(G, nx.DiGraph) and parent is not None:
            for child in children:
                child.remove_parents(parent)
        
        if len(children) !=0:
            delta = size/len(children)
            next_center = center - size/2 - delta/2
            for child in sorted(children, key=lambda child:child.id):
                next_center += delta
                pos = _hierarchy_pos(G,child, size=delta, gap=gap, 
                                    loc=loc + (gap if invert else -gap), center=next_center,
                                    pos=pos, parent=root, invert=invert)
        return pos

            
    return _hierarchy_pos(G, root, size, gap, loc, center, invert=invert)

def export_legend(legend, filename="legend.pdf"):
    fig  = legend.figure
    fig.canvas.draw()
    bbox = legend.get_window_extent().transformed(fig.dpi_scale_trans.inverted())
    fig.savefig(Path.cwd() / "media" / filename, bbox_inches=bbox)

def plot_communication_network(network:CommNetwork, attacker:Attacker=None, palette:str="tab10", layout=hierarchy_layout,
                               ax:Axis|None=None, save_name:str=None, invert:bool=False,
                               show_legend:bool=True, legend_loc="lower center", legend_offset:float=-0.1, save_legend:bool=False,
                               show:bool=True, show_labels:bool=True, node_size:int=400, 
                               legend_size:int=8, label_size:int=10, title_size:int=12,
                               node_types:list|None = None,
                               **kwargs):
    """
    Plots a tree-like and spring layout of the given communication network.
    The visualization shows:
    * Entrypoints for possible cyberattacks
    * Different component types present in the network
    * Components that have been compromised

    Args:
        network (CommNetwork): A specific communication network
        palette (str, optional): Name of seaborn colour palette to use
        layout (function): Function to generate NetworkX Layout (e.g. spring_layout)
            Defaults to hierarchy_layout
    """
    # Simulate attacking the network (allows us to visualize compromised assets)
    if attacker is not None:
        network.reset()
        attacker.attack_network(network)

    node_color_mask = np.full(network.graph.number_of_nodes(), fill_value="#1f78b4", dtype=object)
    node_edge_color_mask = np.full(network.graph.number_of_nodes(), fill_value="#000000", dtype=object)
    edge_color_mask = np.full(network.graph.number_of_edges(), fill_value="#000000", dtype=object)

    node_types = set(node.name for node in network.graph.nodes()) if node_types is None else node_types
    # node_types = ["Sensor Device", "Aggregator", "Controller Device", "Control Center"]
    palette = sns.color_palette(palette, n_colors=len(node_types))
    color_lookup = {k:v for k,v in zip(node_types, palette)}
    
    # Custom Legend
    node_to_pos = {}
    legend_map = {}
    for i, node in enumerate(network.graph.nodes()):
        node_to_pos[node] = i
        color = color_lookup[node.name]
        name = node.name
        node_color_mask[i] = color
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
    # Reset network when done
    if attacker is not None: 
        network.reset()
    
    # >> Plotting <<
    if ax is None:
        _, ax = plt.subplots(nrows=1, ncols=1, figsize=kwargs.get("figsize", (18,6)))
    ax.axis("off")
    label_map = {node:node.id for node in network.graph.nodes()}
    labels, handles = zip(*sorted(zip(*(legend_map.keys(), legend_map.values())), key=lambda t: t[0]))

    # Hierarchical / Tree Visualization of Communication Network
    if layout == hierarchy_layout:
        pos = layout(nx.to_undirected(network.graph), network.root, invert=invert)
    else:
        pos = layout(nx.to_undirected(network.graph))
    nx.draw_networkx_nodes(network.graph, pos=pos, ax=ax,
                           node_size=node_size, node_shape="s", node_color=node_color_mask,
                           linewidths=1.0, edgecolors=node_edge_color_mask)
    nx.draw_networkx_labels(network.graph, pos=pos, labels=label_map, ax=ax,
                            font_size=label_size if show_labels else 0)
    nx.draw_networkx_edges(network.graph, pos=pos, ax=ax, edge_color=edge_color_mask)
    
    if show_legend:
        legend = ax.legend(labels=labels, handles=handles, ncol=1, loc=legend_loc, bbox_to_anchor=(0.0, legend_offset), # ncol=len(labels),
                   title="Legend", fancybox=True, fontsize=legend_size, title_fontsize=title_size)
        if save_legend and save_name is not None:
            export_legend(legend, filename=f"{save_name}_legend.pdf")
    plt.tight_layout()
    
    if save_name is not None:
        plt.gcf().savefig(Path.cwd() / "media" / f"{save_name}.pdf", bbox_inches='tight')
        plt.gcf().savefig(Path.cwd() / "media" / f"{save_name}.png", bbox_inches='tight')
    if show:
        plt.show()
    return handles, labels, pos