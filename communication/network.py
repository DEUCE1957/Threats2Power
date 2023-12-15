import json
import copy
import math
import numpy as np
import networkx as nx
import pandapower
import grid2op
from pathlib import Path as p
from cyber.assets import CyberDevice, Defence, Vulnerability
from communication.graph import CommNode, CommEdge
from communication.components import Device, Aggregator
from procedural.specification import SpecDecoder


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
                 grid:pandapower.pandapowerNet|grid2op.Environment.BaseEnv|None=None,
                 enable_sibling_to_sibling_comm:bool=False,
                 n_entrypoints:int=3):
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
            grid (pandapower.pandapowerNet | grid2op.Environment.BaseEnv | None, optional):
                Specific pandapower grid to map communication network to. Will override 'n_devices'.
                Defaults to None.
            enable_sibling_to_sibling_comm (bool, optional):
                Whether to have lateral connections as well between nodes with the same parent.
                Defaults to False.
            n_entrypoints (int, optional):
                Number of entrypoints for attackers.
                Defaults to 3.
        """
        self.n_devices = n_devices

        # Redundancy (no. of children per aggregator)
        self.children_per_parent = children_per_parent
        self.child_no_deviation = child_no_deviation
        
        with open(network_specs, "r", encoding="utf-8") as f:
            self.specs = json.load(f, cls=SpecDecoder)
        self.grid = grid
        self.enable_sibling_to_sibling_comm = enable_sibling_to_sibling_comm
        self.n_entrypoints = n_entrypoints

        # Generate Communication Network (Procedurally)
        self.n_components = 0
        self.node_ids = []
        self.id_to_node = {} # Does not include root
        self.root = self.build_network(components=[])
        self.entrypoints = []
        self.set_entrypoints()
        self.graph = self.build_graph(self.root, nx.DiGraph())
        
    def build_leaves(self):
        """
        Construct the leaf nodes of the network. Leaf nodes have no children.

        Returns:
            list[TreeNode]: Collection of leaf nodes
        """
        components = []
        device_types = self.specs["device"]["types"]
        # Proportion of devices of each type (default: uniform)
        device_type_prob = self.specs["device"].get("proportion", [1/len(device_types)]*len(device_types))
        if self.grid is None: 
            # Device Type is based on statistic / expected proportion
            device_map = enumerate(np.random.choice(device_types, p=device_type_prob,
                                                    replace=True, size=self.n_devices))
        else:
            # Device Type is based on compatibility with power grid element in PandaPower
            compatabilities = {}
            for device_type in device_types:
                compatible_devices = device_type.get("compatible")
                for compatible_device in compatible_devices:
                    if compatible_device not in compatabilities:
                        compatabilities[compatible_device] = [device_type]
                    else:
                        compatabilities[compatible_device] = compatabilities[compatible_device] + [device_type]

            # Map device type (by name) to probability that device is of that type
            probs = {device_type.get("name"): prob for device_type, prob in zip(device_types, device_type_prob)}

            no_of_devices = 0
            device_map = {}
            if isinstance(self.grid, pandapower.pandapowerNet):
                # Allocation per element (ignored conditions)
                for attr, compatible_device_types in compatabilities.items():
                    attr_df = getattr(self.grid, attr)
                    no_of_attr_devices = attr_df.shape[0]
                    for i in range(no_of_devices, no_of_devices+no_of_attr_devices):
                        # Recalculate probability of choosing each compatible device
                        # Retains original proportion, probabilities must sum to 1
                        local_probs = np.array([probs[device_type.get("name")] for device_type in compatible_device_types])
                        local_probs = (1/sum(local_probs))*local_probs
                        device_map[i] = np.random.choice(compatible_device_types, p=local_probs)
                    no_of_devices += no_of_attr_devices
                device_map = device_map.items()
            elif isinstance(self.grid, grid2op.Environment.BaseEnv):
                # Allocation per substation (evaluates conditions)

                # Grid2Op Obj name mapping
                grid2op_naming = {"load": "loads_id", "gen":"generators_id", "line":"lines_or_id", "storage":"storages_id"}

                for sub_no, sub_name in enumerate(self.grid.name_sub):
                    connected_objs = self.grid.get_obj_connect_to(substation_id=sub_no)
                    
                    for attr, compatible_device_types in compatabilities.items():
                        obj_ids = connected_objs[grid2op_naming[attr]]
                        # Filter / Extend IDs depending on 'device_type' conditions
                        obj_ids = CommNetwork.evaluate_conditions(device_type, self.grid.get_obs(), obj_ids)
                        no_of_attr_devices =len(obj_ids)
                        for i in range(no_of_devices, no_of_devices+no_of_attr_devices):
                            # Recalculate probability of choosing each compatible device
                            # Retains original proportion, probabilities must sum to 1
                            local_probs = np.array([probs[device_type.get("name")] for device_type in compatible_device_types])
                            local_probs = (1/sum(local_probs))*local_probs
                            device_map[i] = np.random.choice(compatible_device_types, p=local_probs)
                        no_of_devices += no_of_attr_devices
                device_map = device_map.items()
                pass
            else:
                raise NotImplemented(f"Grid of type ({type(self.grid)}) is not yet supported.")
        
        # Create Devices
        for i, device_type in device_map:
            device_attrs =  CommNetwork.get_binary_attributes(device_type,
                            ["is_sensor", "is_controller", "is_accessible", "is_autonomous"])
            device = Device(name=device_type.get("name", "Device"),
                            is_controller=device_attrs["is_controller"],
                            is_sensor=device_attrs["is_sensor"],
                            is_autonomous=device_attrs["is_autonomous"],
                            is_accessible=device_attrs["is_accessible"],)
            CommNetwork.attach_cyber_characteristics(device, device_type)
            components.append(device)
            self.node_ids.append(device.id)
            self.id_to_node[device.id] = device
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
            
            if n_children < 0: # Negative cannot exceed remaining no. of components
                n_children = max(n_children, sum_so_far - len(components))
            else: # Positive must at least be 1, up to the maximum no. of remaining components
                n_children = max(1, min(n_children, len(components) - sum_so_far))
            children_per_aggregator.append(np.abs(n_children)) 

            if n_children <= 1: # Assign children to higher level in hierarchy
                skipped_children.extend(components[sum_so_far:sum_so_far+np.abs(n_children)] if \
                                        np.abs(n_children) > 1 else [components[sum_so_far]])
            else: # Assign children to a new aggregator
                # Create the aggregator
                aggregator_type = np.random.choice(self.specs["aggregator"]["types"],
                                                   p=self.specs["aggregator"].get("proportion",None))
                aggregator_attrs =  CommNetwork.get_binary_attributes(aggregator_type, ["is_accessible"])
                aggregator = Aggregator(name=aggregator_type.get("name", "Aggregator"),
                                        is_accessible=aggregator_attrs["is_accessible"])
                CommNetwork.attach_cyber_characteristics(aggregator, aggregator_type)
            
                # Connects Edges
                for i, component in enumerate(components[sum_so_far:sum_so_far+n_children]):
                    component.update_parents(aggregator)
                    CommNetwork.connect_by_edges(aggregator, component)
                    # Connect siblings
                    if i >= 1 and self.enable_sibling_to_sibling_comm:
                        prev_component = components[sum_so_far + (i-1)]
                        if prev_component.__class__ == component.__class__:
                            CommNetwork.connect_by_edges(prev_component, component)

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
            if i >= 1 and self.enable_sibling_to_sibling_comm:
                prev_component = components[i - 1]
                if prev_component.__class__ == component.__class__:
                    CommNetwork.connect_by_edges(prev_component, component)
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
        return self.build_network(components)
    
    def set_entrypoints(self):
        """
        Randomly set entry points at devices or aggregators in the network.
        Excludes control center / root.
        """
        # Reset any existing entrypoints
        for entrypoint in self.entrypoints:
            entrypoint.is_accessible = False
        self.entrypoints = []
        accessible_ids = np.random.choice(self.node_ids,
                                              min(self.n_components - 1, self.n_entrypoints),
                                              replace=False)
        for accessible_id in accessible_ids:
            component = self.id_to_node[accessible_id]
            component.is_accessible = True
            self.entrypoints.append(component)
        
        # self.walk_and_set_entrypoints(self.root, ids_to_match=accessible_components)
    
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
    
    def reset(self):
        """
        Resets the network, including setting new entrypoint(s)
        """
        self.set_entrypoints()
        self.reset_cyber_components(active_node=self.root)
        self.graph = self.build_graph(self.root, graph=nx.DiGraph())

    def reset_cyber_components(self, active_node=None):
        """
        Recursively reset the cyber security status of all components in
        the network, starts from the root node.
        """
        if active_node is None:
            active_node = self.root
        active_node.reset()
        for child in active_node.children:
            self.reset_cyber_components(active_node=child)
    
    @staticmethod
    def evaluate_grid2op_conditions(device_type:dict, obs:grid2op.Observation, obj_ids):
        """
        Checks each object ID at a specific substation to see if it meets the conditions
        given in the network's JSON specifications. 

        Returns:
            list: IDs that satisfy the condition.
        """
        conditions = device_type.get("conditions", None)
        device_ids = copy.deepcopy(obj_ids)
        if conditions is not None and len(obj_ids) > 0:
            for condition in conditions:
                # TODO: Check this works for multiple conditions
                values = getattr(obs, condition["attribute"])[list(set(device_ids))]
                match condition["action"]:
                    case "filter":
                        matching_ids = np.where((values >= condition.get("lb", -math.inf)) & \
                                                (values < condition.get("ub", math.inf)))
                        device_ids = device_ids[matching_ids]
                    case "split":
                        limit = condition.get("limit", math.inf)
                        ids_to_split = device_ids[np.where(values > limit)]
                        
                        new_ids = [obj_id for obj_id in device_ids if obj_id not in ids_to_split]
                        for i, id_to_split in enumerate(ids_to_split):
                            new_ids.extend([id_to_split]*math.ceil(values[i] / limit))
                        device_ids = new_ids
        return device_ids

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
    def attach_cyber_characteristics(component:CyberDevice, configuration:dict):
        """
        Add all Defences and Vulnerabilities specific in a component's configuration
        dictionary to that component.

        Args:
            component (CyberComponent): A component in the communication network.
            configuration (dict): Describes the characteristics of this type of
                component.
        """
        for defence in configuration.get("defences", []):
            component.add_defence(
                Defence(name=defence.get("name", "Defence"),
                        success_distribution=defence["success"],
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