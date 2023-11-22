import itertools
from collections import OrderedDict

class TreeNode():

    """
    Generic node in a hierarchical / tree-like graph.
    Since it is hierarchical, each node can only have 1 parent.
    Each node must be uniquely identifiable and can have children 
    that are reachable through directed edges.
    """

    id_iter = itertools.count()

    def __init__(self, name:str, *args, parent=None, **kwargs) -> None:
        """
        * Can have exactly 1 parent, or none at all.
        * Can have 0 or more children. 
        * Incoming and outgoing edges are stored seperately, which allows for a directional graph.
        * Hashable, which means it can be used as a Node in Networkx. 

        Args:
            name (str): Name of this type of Node
            parent (TreeNode, optional): Node which has this node as its child. Defaults to None.
        """
        super().__init__(*args, **kwargs)
        self.name = name
        self.id = next(self.id_iter)
        self.parents = set([parent] if parent is not None else [])
        self.children = set()
        self.is_leaf = True
        self.outgoing_edges = []
        self.incoming_edges = []
    
    def update_parents(self, *parents):
        """
        Updates parents of current node in the tree.

        Args:
            parents (TreeNode): 1 or more nodes 1 level above this one in the hierarchy.
        """
        self.parents.update(set(parents))
        for parent in parents:
            parent.update_children(self)
    
    def remove_parents(self, *parents):
        """
        Remove parents from current node in the tree.

        Args:
            parents (TreeNode): 1 or more nodes 1 level above this one in the hierarchy.
        """
        for parent in parents:
            parent.remove_children(self)
        self.parents.difference_update(set(parents))
        
    def update_children(self, *children):
        """
        Updates children of this node instance. 

        Args:
            *children (TreeNode): 1 or more nodes below the current
                one in the tree.
        """
        self.children.update(set(children))
        self.is_leaf = False
    
    def remove_children(self, *children):
        """
        Remove children from current node in the tree.

        Args:
            children (TreeNode): 1 or more nodes 1 level above this one in the hierarchy.
        """
        self.children.difference_update(set(children))
        if len(self.children) == 0:
            self.is_leaf = True

    def get_neighbours(self):
        """
        Get all the neighbours of the current node in the tree.

        Returns:
            set[TreeNode]: Set containing all unique neighbours of this node
        """
        neighbours = set()
        for edge in self.outgoing_edges:
            neighbours.add(edge.target)
        for edge in self.incoming_edges:
            neighbours.add(edge.source)
        return neighbours
    
    def add_outgoing_edge(self, other, edge):
        """
        Adds directed edge leading from this node to another one.

        Args:
            other (TreeNode): Node to point to
            edge (TreeNode): Edge to travel along (can have attributes)
        """
        edge.source = self
        self.outgoing_edges.append(edge)
        if edge.target is None:
            other.add_incoming_edge(self, edge)

    def add_incoming_edge(self, other, edge):
        """
        Adds directed edge leading to this node from another one.

        Args:
            other (TreeNode): Node pointing to this Node.
            edge (TreeNode): Edge to travel along (can have attributes)
        """
        edge.target = self
        self.incoming_edges.append(edge)
        if edge.source is None:
            other.add_outgoing_edge(self, edge)

    def reset_edges(self):
        """
        Resets all incoming and outgoing edges.
        Warning: This can isolate this node from its children or parent.
        """
        self.incoming_edges = []
        self.outgoing_edges = []

    def reset_children(self):
        """
        Resets all children.
        Warning: There may still be edges present that point to/from this
        node to its children.
        """
        self.children = set()
    
    def reset_parents(self):
        """
        Resets all parents.
        Warning: There may still be edges present that point to/from this
        node to its parents.
        """
        self.parents = set()
    
    def __str__(self):
        return f"{self.name}_{self.id}"

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return self.name == other.name and self.id == other.id

class Link():

    """
    Generic directed Edge in a Graph, has a source Node and a Target node. Can also have
    attributes associated with it.
    """

    def __init__(self, source:TreeNode, target:TreeNode) -> None:
        """
        Args:
            source (TreeNode, optional): The node where this edge starts. Defaults to None.
            target (TreeNode, optional): The node where this edge ends. Defaults to None.
        """
        super().__init__()
        self.source = source
        self.target = target
        self.attributes = {}

    def to_edge(self):
        """
        Converts this Link to NetworkX edge representation.

        Returns:
            dict[str:obj]: NetworkX mapping for Edge representation
        """
        return dict(u_of_edge=self.source, v_of_edge=self.target, attr=self)

class WiredLink(Link):

    def __init__(self, *args) -> None:
        """
        Physical communication connection between 2 nodes, such as through fibre optic cables.
        """
        super().__init__(*args)

class WirelessLink(Link):

    def __init__(self, *args) -> None:
        """
        Wireless communication connection between 2 nodes, such as through radio waves.
        """
        super().__init__(*args)