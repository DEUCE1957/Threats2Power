from communication.network import CommNetwork
from abc import abstractmethod

class Attacker():
    
    def __init__(self, budget:float, verbose:bool=False, auto_compromise_children:bool=False, repeated_attacks:bool=False):
        """
        Args:
            budget (float): Time available to compromise nodes, starting at the entry point.
            verbose (bool, optional): Whether to print out attack steps.
                Defaults to False
        """
        self.budget = budget
        self.verbose = verbose
        self.auto_compromise_children = auto_compromise_children
        self.repeated_attacks = repeated_attacks
    
    @abstractmethod
    def attack_network(self, comm_network:CommNetwork) -> None:
        pass

class AttackEventSimulator():

    def __init__(self) -> None:
        pass