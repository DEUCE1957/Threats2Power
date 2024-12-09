import numpy as np
import pandapower
from collections import defaultdict
from communication.graph import CommNode
from communication.components import Device, Aggregator

def build_leaves(specs, n_devices=10, grid:pandapower.pandapowerNet=None, prop=None):
    """
    Construct the leaf nodes of the network. Leaf nodes have no children.

    Returns:
        list[TreeNode]: Collection of leaf nodes
    """
    cat_spec = specs["device"]["categories"]
    cat_lookup = {cat["name"]:cat for cat in cat_spec}
    categories = list(cat_lookup.keys())
    

    uniform_device_types = [1/len(categories)]*len(categories)
    # Proportion of devices of each type (default: uniform)
    device_type_prob = specs["device"].get("proportion", uniform_device_types) if prop is None else prop
    if grid is None: 
        # Device Type is based on statistic / expected proportion
        device_population = np.random.choice(categories, p=device_type_prob, replace=True, size=n_devices)
        device_map = enumerate(device_population)
    else: 
        # Apply rules in Specifications to assign 1 or more devices to equipment in the grid.
        compatabilities = defaultdict(list)
        for cat_name, cat in cat_lookup.items():
            compatible_devices = cat.get("compatible")
            for compatible_device in compatible_devices:
                compatabilities[compatible_device].append(cat_name)
        
        # Map device type (by name) to probability that device is of that type
        probs = {device_type.get("name"): prob for device_type, prob in zip(device_types, device_type_prob)}
        # Find all equipment that is compatible with a specific device type
        # If equipment is only compatible with that device type, assing it
        # Otherwise, pick based on proportion

def build_aggregators(components:list[CommNode]):
    """
    Construct the aggregator nodes of the network. Each aggregator node oversees 1 or
    more components 1 level below it in the hierarchy. 

    Args:
        components (list[TreeNode]): Nodes 1 level lower in the hierarchy.

    Returns:
        list[TreeNode]: Collection of aggregator nodes
    """
    
    
def build_root(components:list[CommNode]):
    """
    Construct the root node of the network.

    Args:
        components (list[TreeNode]): Nodes one level below the root in the hierarchy.

    Returns:
        TreeNode: Root of the communication network
    """
    
def build_network(components:list[Device|Aggregator]):
    """
    Recursively build Communication Network composed of Devices and Aggregators.

    Args:
        components (list[Device|Aggregator]): Collection of components (Device or Aggregator) at current level. Defaults to [].

    Returns:
        Aggregator: Root node of tree (represents control center)
    """
    