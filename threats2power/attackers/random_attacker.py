import numpy as np
from .interface import Attacker
from ..communication.components import Device, Aggregator
from ..communication.network import CommNetwork

class RandomAttacker(Attacker):

    """
    Randomly attacks neighboring nodes it can reach.
    Since the choice of the next node to visit is randomzied, the 
    random attacker can and will often retrace it steps.
    Convergence is not gauranteed for large networks.
    """

    __name__ = "RandomAttacker"

    @staticmethod
    def next_available_nodes(current_node:Device|Aggregator):
        """
        Finds all direct neighbours of this node that we can 
        reach through an outgoing connection / edge.

        Args:
            current_node (Node): The active node

        Returns:
            set[Node]: Unique set of all outgoing Nodes
        """
        available_nodes = set()
        # if current_node.is_compromised:
        # Can only attack through outgoing connections
        # I.e. need ability to write data to send payload
        for outgoing_edge in current_node.outgoing_edges:
            node = outgoing_edge.target
            # Don't revisit nodes that were unsucessfuly attacked
            if node.is_worth_attacking() or node.is_compromised:
                available_nodes.add(node)
        return available_nodes
    
    @staticmethod
    def compromise_children(current_node:Device|Aggregator, nodes_compromised):
        """Recursively compromise all children of the current node"""
        for child in current_node.children:
            child.compromise()
            nodes_compromised.add(child)
            nodes_compromised.union(
                RandomAttacker.compromise_children(child, nodes_compromised)
            )
        return nodes_compromised

    def random_walk_with_budget(self, current_node:Device|Aggregator, time_available:float,
                                nodes_available:set[Device|Aggregator]=set(),
                                nodes_visited:set[Device|Aggregator]=set(),
                                nodes_compromised:set[Device|Aggregator]=set(),
                                max_can_compromise:int=1):
        """
        Recursively walk a graph, trying to any compromise components / nodes we come across.
        Stopping criterion:
        * Reached a dead-end (no outgoing edges to follow)
        * Ran out of time to compromise devices
        * Compromised all devices in the network

        Args:
            current_node (Node): The active node
            time_available (float): Time available to try and compromise Nodes
            nodes_available (set[Node], optional): Unique set of nodes in the communication network that 
                have can be visited from the currently compromised set of nodes. Defaults to empty set.
            nodes_visited (set[Node], optional): Unique set of nodes in the communication network that 
                have been visited so far. Defaults to empty set.
            nodes_compromised (set[Node], optional): Unique set of nodes in the communication network that 
                have been compromised so far. Defaults to empty set.
            max_can_compromise (int, optional): Maximum no. of components that can be compromised. Defaults to 1.

        Returns:
            set[Node]: Unique set of communication network components that have been compromised.
            float: Remaining budget
        """
        if self.verbose:
            print(f"--> {current_node.id}", end=" ")
        nodes_visited.add(current_node)
        # Try to Compromise current node
        if current_node.is_compromised:
            is_successful, time_spent = True, 0
        else:
            is_successful, time_spent = current_node.attack(time_available)
        if self.verbose:
            print(f"--> {current_node.id}" + ("S" if is_successful else "F"), end=" ")
        # Lose time spent trying to break this node
        time_available -= time_spent
        if is_successful:
            nodes_available.update(current_node.get_neighbours())
            nodes_available.difference_update(set([current_node]))
            nodes_compromised.add(current_node)
            if self.auto_compromise_children:
                nodes_compromised = self.compromise_children(current_node, nodes_compromised=nodes_compromised)
        if not self.repeated_attacks:
            nodes_available.difference_update(set([current_node]))
        # Still have time available, and haven't compromised entire network yet
        if time_available > 0 and len(nodes_compromised) < max_can_compromise:
            next_nodes = list(nodes_available)
            if len(nodes_available) > 0:
                next_node = np.random.choice(next_nodes)
                (additional_nodes_compromised,
                 time_available) = self.random_walk_with_budget(next_node, time_available,
                                                   nodes_available=nodes_available,
                                                   nodes_visited=nodes_visited,
                                                   nodes_compromised=nodes_compromised,
                                                   max_can_compromise=max_can_compromise)
                nodes_compromised.update(additional_nodes_compromised)
            elif self.verbose:
                print("--> " + ("Dead End" if current_node.is_compromised else "Failed Attack") + 
                      f" ({len(nodes_compromised)} Compromised)")
        elif self.verbose:
            print("--> Fully Compromised" if time_available > 0  else f"--> Ran out of Time (Time left: {time_available})")
        
        # If we've compromised all nodes, or have run out of time, stop.
        return nodes_compromised, time_available
    
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
        total_effort_spent = 0.0
        # for entrypoint in comm_network.entrypoints:
        effort_available = self.budget
        if self.verbose:
            print("Attack Path:\nStart", end=" ")
        (additional_nodes_compromised,
         effort_leftover) = self.random_walk_with_budget(
                                 current_node=np.random.choice(comm_network.entrypoints),
                                 time_available=effort_available,
                                 nodes_available=set(comm_network.entrypoints),
                                 nodes_visited=set(),
                                 nodes_compromised=nodes_compromised,
                                 max_can_compromise=n_components)
        nodes_compromised.update(additional_nodes_compromised)
        total_effort_spent = (effort_available - effort_leftover)
        return nodes_compromised, total_effort_spent