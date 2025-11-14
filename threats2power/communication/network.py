import json
import math
import numpy as np
import pandas as pd
import networkx as nx
import pandapower
from collections import defaultdict
from pathlib import Path as p
from scipy.stats import distributions as distr
from .graph import CommNode, CommEdge
from .components import Equipment, Device, Aggregator
from ..cyber.assets import CyberDevice, Defence, Vulnerability
from ..procedural.specification import SpecDecoder


class CommNetwork(object):
    """
    Procedurally generated communication network composed of Devices and Aggregators.
    Each aggregator has a certain amount of children (can be devices, or other aggregators).
    Entry points are points in the network that can potentially be used by attackers to try
    and compromise the network, such as a Remote connection to a substation.
    """
    __name__ == "CommNetwork"

    def __init__(self, n_devices:int=20,
                 children_per_parent:int=3, child_no_deviation:int=2,
                 network_specs:p=p.cwd() / "specifications" / "Default_specifications.json",
                 grid:pandapower.pandapowerNet|None=None,
                 criticality:dict[str:np.ndarray]=None,
                 crit_norm:bool=False,
                 effort_only:bool=False,
                 sibling_to_sibling_comm:[False, "adjacent", "all"]=False,
                 n_entrypoints:int=1,
                 **kwargs):
        """
        The topology of the communication network is procedurally generated based on the
        parameters set here.

        Args:
            n_devices (int, optional):
                Number of end-devices which collect data or execute commands.
                Defaults to 20.
            children_per_parent (int, optional):
                Level of redundancy in the network, i..e the no. of children per aggregator.
                Defaults to 3.
            child_no_deviation (int, optional):
                Random variation in the redundancy, ignored if redundancy is NONE or FULL.
                Defaults to 2.
            network_specs (str, optional):
                Specifications of network. This is a JSON dictionary that provides details on
                devices, aggregators and the root node.
                Defaults to {}.
            grid (pandapower.pandapowerNet | None, optional):
                Specific pandapower grid to map communication network to. Will override 'n_devices'.
                Defaults to None.
            criticality (dict<str:np.ndarray>):
                Map of physical grid equipment to a criticality level
            crit_norm (bool, optional):
                Whether to normalize the criticality to sum to 1 when all devices are compromised.
                Defaults to False.
            effort_only (bool, optional):
                Whether to only consider effort when performing cyberattacks (i.e. gauranteed
                to succeed if sufficient effort is spent). Overrides specifications and does
                NOT apply to vulnerabilities.
                Defaults to False.
            sibling_to_sibling_comm (str, optional):
                What kind of lateral connections exist between nodes with the same parent.
                Defaults to None.
            n_entrypoints (int, optional):
                Number of entrypoints for attackers.
                Defaults to 1.
        """
        # Specifications
        with open(network_specs, "r", encoding="utf-8") as f:
            self.specs = json.load(f, cls=SpecDecoder)
        
        # Physical Grid
        self.grid = grid
        self.criticality = criticality
        self.crit_norm = crit_norm
        # Criticality if all devices are compromised (for normalization)
        self.maximum_criticality = 0
        self.equip_to_device = {}
        
        # Communication Network
        self.n_devices = n_devices
        self.n_components = 0
        # Procedural parameters
        self.sibling_to_sibling_comm = sibling_to_sibling_comm
        self.children_per_parent = children_per_parent
        self.child_no_deviation = child_no_deviation
        # Lookup Utilities
        self.node_ids = []
        self.id_to_node = {} # Does include root
        self.equipment = []

        # Generate Communication Network (Procedurally)
        self.root = self.build_network(components=[])

        # Cyber Security
        self.effort_only = effort_only
        # Entrypoints are possible starting nodes for cyberattacks
        self.n_entrypoints = n_entrypoints
        self.entrypoints = []
        self.set_entrypoints()
        self.graph = self.build_graph(self.root, nx.DiGraph())
        
    def build_leaves(self, prop:np.ndarray=None):
        """
        Construct the leaf nodes of the network. Leaf nodes have no children.
        
        Args:
            prop [np.ndarray]: Proportion of each kind of device. For example,
            60% Vendor A vs 40% Vendor B.
                Defaults to None.
        
        Returns:
            list[TreeNode]: Collection of leaf nodes
        """
        components = []

        cat_spec = self.specs["device"]["categories"]
        cat_lookup = {cat["name"]:cat for cat in cat_spec}
        categories = list(cat_lookup.keys())

        # Proportion of devices of each type (default: uniform)
        uniform_device_types = [1/len(categories)]*len(categories)
        device_type_prob = self.specs["device"].get("proportion", uniform_device_types) if prop is None else prop
        # Device Type is based on statistic / expected proportion
        if self.grid is None:
            device_population = np.random.choice(categories, p=device_type_prob, replace=True, size=self.n_devices)
            devices = [(i, cat_name, 1, None) for i, cat_name in enumerate(device_population)]
        # Apply rules in Specifications to assign 1 or more devices to equipment in the grid.
        else:
            # Map device category (by name) to probability that device is of that category
            prob_lookup = {cat_name: prob for cat_name, prob in zip(categories, device_type_prob)}

            # Find Voltage Level for all equipment
            bus_lookup = {"line":"from_bus", "dcline":"from_bus", "impedance":"from_bus", "gen":"bus", "sgen":"bus",
                          "load":"bus","switch":"bus", "motor":"bus", "asymmetric_load":"bus", "asymmetric_sgen":"bus",
                          "shunt":"bus", "ward":"bus", "xward":"bus", "storage":"bus"}
            volt_lookup = {}
            for eqp_name, bus_attr in bus_lookup.items():
                equip_df = getattr(self.grid, eqp_name)
                buses = getattr(equip_df, bus_attr)
                volt_lookup[eqp_name] = self.grid.bus.loc[buses].vn_kv.reset_index(drop=True)

            compat = {}
            for i, cat_name in enumerate(categories):
                cat = cat_lookup[cat_name]
                comp_devices = cat.get("compatible")
                for device_kind, actions in comp_devices.items():
                    equip_df = getattr(self.grid, device_kind)

                    # DataFrame with probability of choosing each Device Category (e.g. different types of smart meters)
                    if device_kind not in compat:
                        compat[device_kind] = dict(
                            probs=pd.DataFrame(np.zeros((equip_df.shape[0], len(categories))), columns=categories),
                            splits=pd.DataFrame(np.ones((equip_df.shape[0], len(categories))), columns=categories, dtype=np.int16),
                        )
                    # Filter out equipment that doesn't meet conditions
                    if "filter" in actions:
                        conditions = actions["filter"] # Can filter by multiple conditions
                        mask = np.ones(equip_df.shape[0], dtype=bool)
                        for condition in conditions:
                            criteria = equip_df.get(condition["attribute"]) if condition["attribute"] != "voltage" else volt_lookup[device_kind]
                            if "eq" in condition:
                                mask = mask & (criteria == condition["eq"])
                            else:
                                mask = mask & (criteria >= condition.get("lb", -math.inf)) & \
                                              (criteria <= condition.get("ub",  math.inf))
                        compat[device_kind]["probs"].loc[mask, cat_name] = prob_lookup[cat_name]
                    else:
                        compat[device_kind]["probs"].loc[:, cat_name] = prob_lookup[cat_name]

                    # Splits equipment that exceeds limits
                    if "split" in actions:
                        condition = actions["split"] # Can only split by a single condition
                        criteria = equip_df.get(condition["attribute"])
                        min_splits = criteria.floordiv(condition.get("limit", math.inf)).astype(np.int16)
                        leftover_split = (criteria.mod(condition.get("limit", math.inf)) > 0).astype(np.int16)
                        compat[device_kind]["splits"].loc[:, cat_name] = min_splits + leftover_split
                    
            select_compatible_device_category = lambda p: np.random.choice(categories, p=p)
                
            no_of_devices = 0
            devices = []
            for device_kind, compatability in compat.items():
                # Normalize probabilities (must sum to 1)
                probs = compatability["probs"]
                probs = probs.div(probs.sum(axis=1), axis=0).dropna()
                if len(probs) == 0: # No compatible components
                    continue
                
                # Get information about the connected equipment
                equip_df = getattr(self.grid, device_kind)

                # Select device category
                equip_df["Category"] = probs.apply(select_compatible_device_category, axis=1)
                mask = ~equip_df.Category.isna()
                equip_df = equip_df.dropna(subset=["Category"])

                # Split device if equipment exceeds size limit
                def select_no_of_splits(row):
                    category = equip_df.Category.loc[row.name].item()
                    n_splits = row[category]
                    return n_splits
                
                equip_df["Splits"] = compatability["splits"].loc[mask].apply(select_no_of_splits, axis=1)

                # Add Device Idx, Device Category, No. of Splits and Associated Equipment to devices
                for count, idx in enumerate(equip_df.index):
                    i = no_of_devices + count
                    cat_name = equip_df.loc[idx, "Category"]
                    n_splits = equip_df.loc[idx, "Splits"]
                    # Link the Criticality of the component (if it is defined)
                    if self.criticality is None:
                        equip = Equipment(idx, kind=device_kind)
                    else:
                        # Criticality is divided by number of splits (!)
                        criticality = self.criticality[device_kind][idx] / n_splits
                        equip = Equipment(idx, kind=device_kind,
                                          criticality=criticality)
                        self.maximum_criticality += criticality
                    devices.append((i, cat_name, n_splits, equip))
                # Add additional devices corresponding to n_splits
                # devices.extend([(no_of_devices + count, equip_df.loc[idx, "Category"], equip_df.loc[idx, "Splits"],
                #                  equip) for count, idx in enumerate(equip_df.index)])
                no_of_devices = len(devices)

        # Create Devices
        self.n_devices = len(devices)
        for i, cat_name, n_splits, equip in devices:
            cat = cat_lookup[cat_name]
            device_name = cat.get("name", "Device")
            device_attrs =  CommNetwork.get_binary_attributes(cat,
                            ["is_sensor", "is_controller", "is_accessible", "is_autonomous"])
            for _ in range(n_splits):
                # Create and configure device
                device = Device(name=device_name,
                                equipment=equip,
                                is_controller=device_attrs["is_controller"],
                                is_sensor=device_attrs["is_sensor"],
                                is_autonomous=device_attrs["is_autonomous"],
                                is_accessible=device_attrs["is_accessible"])
                CommNetwork.attach_cyber_characteristics(device, cat)
                
                # Find all devices connected to specific physical equipment (e.g. a generator)
                if equip is not None:
                    if equip.kind not in self.equip_to_device:
                        self.equip_to_device[equip.kind] = defaultdict(list)
                    self.equip_to_device[equip.kind][equip.name].append(device.id)
                
                # Lookup Utilities
                self.node_ids.append(device.id)
                self.equipment.append(equip)
                self.id_to_node[device.id] = device

                # Add device to components (to allocate to aggregators)
                components.append(device)
                self.n_components += 1
        return components
    
    def build_aggregators(self, components:list[CommNode]):
        """
        Construct the aggregator nodes of the network. Each aggregator node oversees 1 or
        more components 1 level below it in the hierarchy. 

        Args:
            components (list[TreeNode]): Nodes 1 level lower in the hierarchy.

        Returns:
            list[TreeNode]: Collection of aggregator nodes
        """
        aggregators = []

        # Allocate children/components to each Aggregator
        children_per_aggregator = []
        skipped_children = []
        while (sum_so_far := sum(children_per_aggregator)) != len(components):
            # Allow some variation in no. of children
            if self.child_no_deviation > 0:
                random_deviation = np.random.randint(-self.child_no_deviation, self.child_no_deviation + 1)
            else:
                random_deviation = 0
            # No. of children per aggregator (can be negative)
            n_children = self.children_per_parent + random_deviation
            
            if self.specs["topology"] == "flat": # Flat Communication Network
                n_children = len(components)
            elif n_children < 0: # Negative cannot exceed remaining no. of components
                n_children = max(n_children, sum_so_far - len(components))
            else: # Positive must at least be 1, up to the maximum no. of remaining components
                n_children = max(1, min(n_children, len(components) - sum_so_far))
            children_per_aggregator.append(np.abs(n_children))

            if n_children <= 1: # Assign children to higher level in hierarchy
                skipped_children.extend(components[sum_so_far:sum_so_far+np.abs(n_children)] if \
                                        np.abs(n_children) > 1 else [components[sum_so_far]])
            else: # Assign children to a new aggregator
                # Create the aggregator
                aggregator_category = np.random.choice(self.specs["aggregator"]["categories"],
                                                       p=self.specs["aggregator"].get("proportion",None))
                aggregator_attrs =  CommNetwork.get_binary_attributes(aggregator_category, ["is_accessible"])
                aggregator = Aggregator(name=aggregator_category.get("name", "Aggregator"),
                                        is_accessible=aggregator_attrs["is_accessible"])
                CommNetwork.attach_cyber_characteristics(aggregator, aggregator_category)
            
                # Connects Edges
                for i, component in enumerate(components[sum_so_far:sum_so_far+n_children]):
                    component.update_parents(aggregator)
                    CommNetwork.connect_by_edges(aggregator, component)
                    # Connect siblings
                    if i >= 1 and self.sibling_to_sibling_comm:
                        if self.sibling_to_sibling_comm == "adjacent":
                            prev_component = components[sum_so_far + (i-1)]
                            if prev_component.__class__ == component.__class__:
                                CommNetwork.connect_by_edges(prev_component, component)
                        else: # All siblings connected together
                            for other_component in components[sum_so_far:sum_so_far+n_children]:
                                if other_component != component:
                                    CommNetwork.connect_by_edges(other_component, component)

                # Keep Track of Nodes
                aggregators.append(aggregator)
                self.node_ids.append(aggregator.id)
                self.id_to_node[aggregator.id] = aggregator
                self.n_components += 1
        aggregators.extend(skipped_children)
        return aggregators
    
    def build_root(self, components:list[CommNode]):
        """
        Construct the root node of the network.

        Args:
            components (list[TreeNode]): Nodes one level below the root in the hierarchy.

        Returns:
            TreeNode: Root of the communication network
        """
        # Create the root node
        root_type = self.specs["root"]
        root_attrs =  CommNetwork.get_binary_attributes(root_type, ["is_accessible"])
        root = Aggregator(name=root_type.get("name", "Control Center"),
                          is_accessible=root_attrs["is_accessible"])
        CommNetwork.attach_cyber_characteristics(root, root_type)
        
        for i, component in enumerate(components):
            component.update_parents(root)
            CommNetwork.connect_by_edges(root, component)
            # Connect siblings
            if i >= 1 and self.sibling_to_sibling_comm:
                prev_component = components[i - 1]
                if prev_component.__class__ == component.__class__:
                    CommNetwork.connect_by_edges(prev_component, component)
        self.node_ids.append(root.id)
        self.id_to_node[root.id] = root
        self.n_components += 1
        return root
        
    def build_network(self, components:list[Device|Aggregator]):
        """
        Recursively build Communication Network composed of Devices and Aggregators.

        Args:
            components (list[Device|Aggregator]): Collection of components (Device or Aggregator) at current level. Defaults to [].

        Returns:
            Aggregator: Root node of tree (represents control center)
        """
        if len(components) == 0:
            components = self.build_leaves()
        elif len(components) > 1:
            components = self.build_aggregators(components)
        else:
            root = self.build_root(components)
            return root
        # Normalize criticality of components to [0, 1] range
        if self.crit_norm and self.maximum_criticality > 0:
            for equip in self.equipment:
                # Also affects equipment reference inside Device instances
                equip.criticality = equip.criticality / self.maximum_criticality
        return self.build_network(components)
    
    def set_entrypoints(self, possible_entrypoints:int|None=None, rng:np.random.Generator|None=None):
        """
        Randomly set entry points at devices or aggregators in the network.
        Excludes control center / root.
        """
        # Reset any existing entrypoints
        for entrypoint in self.entrypoints:
            entrypoint.is_accessible = False
        self.entrypoints = []
        if possible_entrypoints is not None: # Select from a list of specific entrypoints
            accessible_ids = possible_entrypoints if isinstance(possible_entrypoints, list) else [possible_entrypoints]
        else: # Select from a list of all assets
            choice = np.random.choice if rng is None else rng.choice
            accessible_ids = choice(self.node_ids,
                                    min(self.n_components - 1, self.n_entrypoints),
                                    replace=False)
        for accessible_id in accessible_ids:
            component = self.id_to_node[accessible_id]
            component.is_accessible = True
            self.entrypoints.append(component)
    
    def build_graph(self, root:Aggregator, graph:nx.DiGraph):
        """
        Construct NetworkX Graph from connected Aggregators / Devices

        Args:
            root (Aggregator): Root node of the Communication Network (e.g. the Control Center)
        Returns:
            networkx.DiGraph: Directional NetworkX Graph, with added nodes/edges
        """
        graph.add_node(root)
        for edge in root.outgoing_edges:
            graph.add_edge(edge.source, edge.target, p=edge.target.get_prob_to_compromise())
        for edge in root.incoming_edges:
            graph.add_edge(edge.target, edge.source, p=edge.source.get_prob_to_compromise())
        for child in root.children:
            graph = self.build_graph(child, graph)
        return graph
    
    def walk_and_set_entrypoints(self, root:Aggregator, ids_to_match:np.ndarray):
        """
        Walk the tree, modifying indices that are present in the 'idcs_to_match' array.

        Args:
            root (Aggregator): _description_
            attr_name (str): Name of attribute to modify
            set_value (object): Value to set the attribute to set
            idcs_to_match (np.ndarray): Idcs (in walking order) to modify
            idx (int, optional): Current index in walk. Defaults to 0.

        Returns:
            int: Last visited index
        """
        if root.id in ids_to_match:
            root.is_accessible = True
            self.entrypoints.append(root)
        for child in root.children:
            self.walk_and_set_entrypoints(child, ids_to_match)
    
    def reset(self, possible_entrypoints:int|None=None, rng:np.random.Generator|None=None):
        """
        Resets the network, including setting new entrypoint(s)
        """
        self.set_entrypoints(possible_entrypoints, rng=rng)
        self.reset_cyber_components(active_node=self.root, rng=rng)
        self.graph = self.build_graph(self.root, graph=nx.DiGraph())

    def reset_cyber_components(self, active_node=None, rng:np.random.Generator|None=None):
        """
        Recursively reset the cyber security status of all components in
        the network, starts from the root node.
        """
        if active_node is None:
            active_node = self.root
        active_node.reset(rng)
        for child in active_node.children:
            self.reset_cyber_components(active_node=child, rng=rng)

    @staticmethod
    def get_binary_attributes(configuration:dict, attributes:list[str], default:bool=False):
        """
        Retrieve named (binary/boolean) attributes from a configuration dictionary for a
        specific component type.

        Args:
            configuration (dict): Describes the attributes of a component
            attributes (list[str]): Names of attributes to try and retrieve
            default (bool, optional): Default value to use if attribute cannot be found.
                Defaults to False.

        Returns:
            dict[str:bool]: _description_
        """
        attrs = {}
        for attr_name in attributes:
            attr = configuration.get(attr_name, default)
            attrs[attr_name] = attr if type(attr) is bool else bool(attr.rvs())
        return attrs

    @staticmethod
    def attach_cyber_characteristics(component:CyberDevice, configuration:dict, effort_only:bool=False):
        """
        Add all Defences and Vulnerabilities specific in a component's configuration
        dictionary to that component.

        Args:
            component (CyberComponent): A component in the communication network.
            configuration (dict): Describes the characteristics of this type of
                component.
            effort_only (bool): Whether to only consider effort spent when 
                determining success. If True, compromise is gauranteed if
                enough effort is spent. Does NOT affect vulnerabilities (!). 
                Defaults to False.
        """
        for defence in configuration.get("defences", []):
            component.add_defence(
                Defence(name=defence.get("name", "Defence"),
                        success_distribution=distr.bernoulli(p=1.0) if effort_only else defence["success"],
                        effort_distribution=defence["effort"])
            )
        for vulnerability in configuration.get("vulnerabilities", []):
            component.attach_vulnerability(
                Vulnerability(name=vulnerability.get("name", "Vulnerability"))
            )

    @staticmethod
    def connect_by_edges(source:Device|Aggregator, target:Device|Aggregator):
        """
        Adds two-way communication edges depending on whether child is a sensor and/or controller or aggregator.
        TODO: One-way communication

        Args:
            source (Device|Aggregator): Component to connect from
            target (Device|Aggregator): Component to connect to
        """
        source.add_incoming_edge(target, CommEdge(None, None))
        target.add_outgoing_edge(source, CommEdge(None, None))

    @staticmethod
    def show_tree(root:Aggregator, s:str="", depth:int=0):
        """
        Recursively prints out structure of communication network using whitespace to denote deeper components.

        Args:
            root (Aggregator): _description_
            s (str, optional): _description_. Defaults to "".
            depth (int, optional): _description_. Defaults to 0.
            include_hash (bool): Whether to include the hash ID of each node

        Returns:
            str: String representing the network architecture
        """
        s += f"{depth*'   '}{root}\n"
        for child in root.children:
            s = CommNetwork.show_tree(child, s=s, depth=depth+1)
        return s
    
    def get_compromised_devices(self, root:Aggregator, compromised:set=set()):
        """
        Walk the tree, fetching all compromised assets.

        Args:
            root (Aggregator): _description_
            attr_name (str): Name of attribute to modify
            set_value (object): Value to set the attribute to set
            idcs_to_match (np.ndarray): Idcs (in walking order) to modify
            idx (int, optional): Current index in walk. Defaults to 0.

        Returns:
            int: Last visited index
        """
        if root.is_compromised and isinstance(root, Device):
            compromised.add(root)
        for child in root.children:
            new_compromised = self.get_compromised_devices(child, compromised)
            compromised = new_compromised.union(compromised)
        return compromised