import json
import numpy as np
import networkx as nx
from pathlib import Path as p
from tree import TreeNode, Link
from cyber import CyberComponent, Defence, Vulnerability
from network_specification import SpecDecoder

class Aggregator(CyberComponent, TreeNode):
    __name__ = "Aggregator"

    def __init__(self, *args, **kwargs) -> None:
        """
        Generic communication network component that aggregates data from 1 or more sources.
        The Aggregator can be hacked, which can also impact the reliability of all downstream data. 
        """
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"{self.name}(id={self.id}, is_accessible={self.is_accessible})"

class Device(CyberComponent, TreeNode):
    __name__ = "Device"

    def __init__(self, is_controller:bool, is_sensor:bool, is_autonomous:bool=False, *args, **kwargs) -> None:
        """
        Generic communication network component that collects data and/or acts in the real world.
        The device can be hacked, which impacts the trustworthiness of the data the device emits.

        Args:
            is_controller (bool): Whether the device controls a real-world object,
                such as the power output of battery
            is_sensor (bool): Whether the device collects data about a real-world object,
                such as the state of charge of a battery
            is_autonomous (bool): Whether the device can independently make decisions
                such as when to charge the battery. Always false is device is not a controller.
        """
        super().__init__(*args, **kwargs)
        self.is_controller = is_controller
        self.is_autonomous = False if not self.is_controller else is_autonomous
        self.is_sensor = is_sensor

    def __str__(self):
        return (f"{self.name}(id={self.id}, is_controller={self.is_controller}, " +
                f"is_autonomous={self.is_autonomous}, is_sensor={self.is_sensor}, is_accessible={self.is_accessible})")

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
        for _ in range(self.n_devices):
            device_type = np.random.choice(self.specs["device"]["types"],
                                           p=self.specs["device"].get("commonness",None))
            device_attrs =  CommNetwork.get_binary_attributes(device_type,
                            ["is_sensor", "is_controller", "is_accessible", "is_autonomous"])
            if not device_attrs["is_controller"] and not device_attrs["is_sensor"]:
                device_attrs["is_sensor"] = True
            device = Device(name=device_type.get("name", "Device"),
                            is_controller=device_attrs["is_controller"],
                            is_sensor=device_attrs["is_sensor"],
                            is_autonomous=device_attrs["is_autonomous"],
                            is_accessible=device_attrs["is_accessible"],)
            CommNetwork.attach_cyber_characteristics(device, device_type)
            components.append(device)
            self.node_ids.append(device.id)
            self.id_to_node[device.id] = device
        return components
    
    def build_aggregators(self, components:list[TreeNode]):
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
                                                   p=self.specs["aggregator"].get("commonness",None))
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
        aggregators.extend(skipped_children)
        return aggregators
    
    def build_root(self, components:list[TreeNode]):
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
            self.n_components += len(components)
        elif len(components) > 1:
            components = self.build_aggregators(components)
            self.n_components += len(components)
        else:
            root = self.build_root(components)
            self.n_components += 1
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
            graph.add_edge(edge.source, edge.target)
        for edge in root.incoming_edges:
            graph.add_edge(edge.target, edge.source)
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
    def attach_cyber_characteristics(component:CyberComponent, configuration:dict):
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
        source.add_incoming_edge(target, Link(None, None))
        target.add_outgoing_edge(source, Link(None, None))

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