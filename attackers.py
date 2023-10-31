import numpy as np
from tree import TreeNode
from comm_network import CommNetwork
from abc import abstractmethod
from collections import deque

class Attacker():
    
    def __init__(self, budget:float, verbose:bool=False):
        """
        Args:
            budget (float): Time available to compromise nodes, starting at the entry point.
            verbose (bool, optional): Whether to print out attack steps.
                Defaults to False
        """
        self.budget = budget
        self.verbose = verbose
    
    @abstractmethod
    def attack_network(self, comm_network:CommNetwork) -> None:
        pass

class RandomAttacker(Attacker):

    """
    Randomly attacks neighboring nodes it can reach.
    Since the choice of the next node to visit is randomzied, the 
    random attacker can and will often retrace it steps.
    Convergence is not gauranteed for large networks.
    """

    @staticmethod
    def next_available_nodes(current_node:TreeNode):
        """
        Finds all direct neighbours of this node that we can 
        reach through an outgoing connection / edge.

        Args:
            current_node (Node): The active node

        Returns:
            set[Node]: Unique set of all outgoing Nodes
        """
        available_nodes = set()
        if current_node.is_compromised:
            # Can only attack through outgoing connections
            # I.e. need ability to write data to send payload
            for outgoing_edge in current_node.outgoing_edges:
                node = outgoing_edge.target
                available_nodes.add(node)
        return available_nodes

    def random_walk_with_budget(self, current_node:TreeNode, time_available:float,
                                attack_path:deque=deque(), nodes_compromised:set[TreeNode]=set(),
                                max_can_compromise:int=1):
        """
        Recursively walk a graph, trying to any compromise components / nodes we come across.
        Stopping criterion:
        * Reached a dead-end (no outgoing edges to follow)
        * Ran out of time to compromise devices
        * Compromised all devices in the network

        Args:
            current_node (Node): The active node
            time_available (float): Time available to try and compromise Nodes.
            nodes_compromised (set[Node], optional): Unique set of nodes in the communication network that 
                have been compromised so far. Defaults to empty set.
            max_can_compromise (int, optional): Maximum no. of components that can be compromised. Defaults to 1.

        Returns:
            set[Node]: Unique set of communication network components that have been compromised.
        """
        attack_path.append(current_node.id)
        # Try to Compromise current node
        if current_node.is_compromised:
            is_successful, time_spent = True, 0
        else:
            is_successful, time_spent = current_node.attack(time_available)
        # Lose time spent trying to break this node
        time_available -= time_spent
        if is_successful:
            nodes_compromised.add(current_node)
        # Still have time available, and haven't compromised entire network yet
        if time_available > 0 and len(nodes_compromised) < max_can_compromise:
            available_nodes = RandomAttacker.next_available_nodes(current_node)
            # Don't revisit nodes that were unsuccessfully attacked (not worth attacking)
            next_nodes = [node for node in available_nodes if \
                          node.is_worth_attacking() or node.is_compromised]
            if len(next_nodes) == 0:
                current_node.is_deadend = True
                print([node.is_deadend for node in nodes_compromised])
                next_nodes = list([node for node in nodes_compromised if not node.is_deadend])
            if len(next_nodes) > 0:
                next_node = np.random.choice(next_nodes)
                attack_path, new_nodes_compromised = \
                    self.random_walk_with_budget(next_node, time_available,
                                                 attack_path=attack_path,
                                                 nodes_compromised=nodes_compromised,
                                                 max_can_compromise=max_can_compromise)
                nodes_compromised = nodes_compromised.union(new_nodes_compromised)
            else:
                attack_path.append("Dead End")
    
        # If we've compromised all nodes, or have run out of time, stop.
        return attack_path, nodes_compromised
    
    def attack_network(self, comm_network:CommNetwork):
        """
        Randomly attack network from all entrypoints at the same time. 
        There is no coordinated strategy behind this attacker, it wanders through the
        communication network without regard for the position or importance of components.
        Each entry point starts with the same attack budget.

        Args:
            comm_network (CommNetwork): Procedurally generated Communication Network
        """
        n_components = comm_network.n_components
        nodes_compromised = set()
        for entrypoint in comm_network.entrypoints:
            time_available = self.budget
            attack_path, new_nodes_compromised = \
                self.random_walk_with_budget(entrypoint, time_available,
                                             attack_path = deque(),
                                             nodes_compromised=nodes_compromised,
                                             max_can_compromise=n_components)
            nodes_compromised = nodes_compromised.union(new_nodes_compromised)
            if self.verbose:
                print(f"Attack Path:\n{' --> '.join([str(elt) for elt in attack_path])}")

attacker = RandomAttacker(budget=52, verbose=True)