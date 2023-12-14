import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from communication.network import CommNetwork
from abc import abstractmethod

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

class AttackEventSimulator():

    def __init__(self) -> None:
        pass