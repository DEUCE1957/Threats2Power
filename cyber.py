import itertools
from math import isclose
from collections import OrderedDict
from scipy.stats import distributions as distr


class Vulnerability():

    """
    Modifier that effects the effectivness of a defence. That is if a Vulnerability 
    is present and is discovered, it is easier to compromise the asset.
    """

    def __init__(self, name:str) -> None:
        super().__init__()
        self.name = name
        self.exploited = False

    def exploit(self) -> (float, float):
        """
        Exploit vulnerability to reduce difficulty of breaking associated defence.
        Can only be done once.

        Returns:
            float: Decimal improvement in success rate.
                Success rate can at most be 1.0 (100%).
            float: Effort removed by exploit.
                Effort can at minimum be 0 (instantaneous).
        """
        success_rate_improvement = 0
        effort_removed = 0
        self.exploited = True
        return success_rate_improvement, effort_removed

class Defence():
    """
    Generic Cyber Security defence, has an associated probability for success and a
    certain amount of time required to compromise it.
    The time spent attacking the defence is remembered, so multiple independent
    attempts are more likely to succeed.
    """

    def __init__(self, name:str, p:float=1.0,
                 vulnerability:Vulnerability=Vulnerability("NoVulnerability"),
                 success_distribution:distr.rv_discrete=distr.bernoulli,
                 effort_distribution:distr.rv_continuous=distr.uniform(loc=0.0, scale=0.0)) -> None:
        """
        Cyber security defence is initialized with a set amount of time/effort needed
        to try and break the defence.
        Regardless of time/effort spent, a defence may not necessarily be breakable.

        Args:
            name (str):
                Name of this defence
            p (float, optional):
                Probability of successful compromise, given infinite time.
                Defaults to 1.0.
            success_distribution (scipy.stats.distributions.rv_discrete, optional):
                Distribution of chance to break the defence, given infinite effort.
                Defaults to Bernoulli.
            effort_distribution (scipy.stats.distributions.rv_continuous, optional):
                Distribution of effort/time needed to break this defence.
                Defaults to instantaneous.
        """
        self.name = name
        self.vulnerability = vulnerability
        self.success_distr = success_distribution
        self.p = p
        self.effort_to_compromise = effort_distribution.rvs()
        self.is_compromised = False
        # Total time/effort spent attacking this defence
        self.effort_spent = 0

    def remove_vulnerability(self):
        self.vulnerability = Vulnerability("NoVulnerability")

    def exploit_vulnerability(self):
        """
        Exploit any present vulnerability in the defence to reduce the time/effort
        required to break it and/or increase the chance of succeeding. 
        """
        # If vulnerability has already been used, no benefit from using it again
        if self.vulnerability.exploited:
            self.effort_to_compromise -= 0
            self.p += 0
        else:
            success_rate_improvement, effort_removed = self.vulnerability.exploit()
            self.p = min(1, self.p + success_rate_improvement)
            self.effort_to_compromise = max(0, self.effort_to_compromise - effort_removed)
        
    def is_worth_attacking(self) -> bool:
        """Whether this Defence is still worth attacking"""
        return False if isclose(self.effort_spent, self.effort_to_compromise) else True
    
    def attack(self, budget:float, exploit_vulnerability:bool=False) -> (bool, float):
        """
        Attack this defence with a certain time budget available.
        Note that effort is not an exact measure, though it approximately represents days.

        Args:
            budget (float): Amount of time available to attack the defence
            exploit_vulnerability (bool): Whether to exploit any present vulnerability in the defence.
                If True then the attacker knows the vulnerability is present and has the skill to exploit it.
                Defaults to False.

        Returns:
            bool: Whether the attack is successful
            float: How much time/effort was spent
        """
        if exploit_vulnerability:
            self.exploit_vulnerability()
        if (self.effort_to_compromise - self.effort_spent) > budget:
            # Not enough time available to break this defence
            self.effort_spent -= budget
            return False, budget
        budget_used = self.effort_to_compromise - self.effort_spent
        # Spent the exact amount of effort required to try and break the defence
        self.effort_spent = self.effort_to_compromise
        # If 'can_be_successful' is False then no amount of effort can break this defence
        can_be_successful = self.success_distr(p=self.p).rvs()
        if can_be_successful:
            self.is_compromised = True
        return can_be_successful, budget_used

class CommmonDefences():
    """
    Factory for common types of Communication Network cyber defences.
    """

    @classmethod
    def easy_and_certain(cls) -> Defence:
        """100% chance to succeed and will only take a little amount of effort to break."""
        return Defence("EasyAndCertain", p=1.0,
                effort_distribution=distr.expon(scale=1/1.0))
    
    @classmethod
    def easy_and_uncertain(cls) -> Defence:
        """50% chance to succeed and will only take no effort to break."""
        return Defence("EasyAndUncertain", p=0.5)

    @classmethod
    def hard_and_certain(cls) -> Defence:
        """100% chance to succeed but will take a large amount of effort to break."""
        return Defence("HardAndCertain", p=1.0,
                 effort_distribution=distr.expon(scale=1/0.1))

    @classmethod
    def hard_and_uncertain(cls) -> Defence:
        """50% chance to succeed and will take a large amount of effort to break."""
        return Defence("HardAndUncertain", p=0.5,
                effort_distribution=distr.expon(scale=1/0.1))

    @classmethod
    def very_hard_and_uncertain(cls) -> Defence:
        """50% chance to succeed and will take a tremendous amount of effort to break."""
        return Defence("VeryHardAndUncertain", p=0.5,
                effort_distribution=distr.expon(scale=1/0.01))
       
    @classmethod
    def impossible(cls) -> Defence:
        """0% chance to succeed and will no effort to try and break."""
        return Defence("Impossible", p=0)

class CyberComponent():

    """
    A Cyber Component is any electronic device that can be hacked. In order to
    attempt to hack it must be next to an open or already compromised connection.
    The time taken to compromise the component depends on its defences and vulnerabilities.
    """

    def __init__(self, is_accessible:bool, *args, is_compromised:bool=False, **kwargs) -> None:
        """
        A Cyber Component can be accessible (directly open to attack) and/or be
        compromised by an attack.
        Inaccessible cyber components can potentially still be attacked
        from neighboring components.

        Args:
            is_accessible (bool): Whether the component is an entry point to
                the Communication Network
            is_compromised (bool, optional): Whether the component has been compromised.
                Defaults to False.
        """
        super().__init__(*args, **kwargs)
        self.is_accessible = is_accessible
        self.is_compromised = is_compromised
        self.is_deadend = False
        self.total_effort_spent = 0.0
        self.defences = OrderedDict()

    def attack(self, budget:float) -> (bool, float):
        """
        Attack this component with a certain time budget available. Note that time is not an exact measure.
        To successfuly compromise the device, all defences must be broken.

        Args:
            budget (float): Amount of time available to attack the defence

        Returns:
            bool, float: Whether the attack is successful, how much time was spent
        """
        # TODO: Must we really break all defences to compromise an asset?
        effort_spent = 0.0
        for defence in self.defences.values():
            if defence.is_compromised:
                is_successful, effort = True, 0
            else:
                is_successful, effort = defence.attack(budget)
            effort_spent += effort
            budget -= effort
            # Could not get past the defence, or ran out of time
            if not is_successful or budget <= 0:
                break
        # If attack is successful mark this component as compromised
        if is_successful and budget >= 0:
            self.is_compromised = True
        self.total_effort_spent += effort_spent
        return is_successful, effort_spent
    
    def is_worth_attacking(self) -> bool:
        """
        Evaluates whether all Defences have been attacker with the 
        required amount of effort, regardless of success.
        If any defences remain, then this method will return False.

        Returns:
            bool: Whether additional attacks can make progress
        """
        for defence in self.defences.values():
            if defence.is_worth_attacking():
                return True
        return False
        
    def add_defence(self, defence:Defence):
        """
        Add a defence to the existing set of defences.

        Args:
            defence (Defence): A cyber security defence mechanism, such as a firewall.
        """
        if defence.name not in self.defences:
            self.defences[defence.name] = defence
        else:
            raise KeyError(f"Defence mechanism of type '{defence.name}' already" +
                           "present in the set of Defences")

    def remove_defence(self, defence:Defence|str) -> bool:
        """
        Remove a defence (by name or reference) from the set of defences.

        Args:
            defence (Defence|str): Reference to defence object

        Returns:
            bool: Whether the defence was found and removed.
        """
        name = defence.name if isinstance(defence, Defence) else defence
        if name in self.defences:
            del self.defences[name]
            return True
        return False

    def attach_vulnerability(self, defence:Defence|str, vulnerability:Vulnerability) -> bool:
        """
        Attach a vulnerability to a specific defence. 

        Args:
            defence (Defence | str): A cyber security defence mechanism, such as a firewall.
            vulnerability (Vulnerability): A vulnerability in the defence, that can be exploited.

        Returns:
            bool: Whether the vulnerability was successfully attached to the defence
        """
        name = defence.name if isinstance(defence, Defence) else defence
        if name in self.defences:
            self.defences[name].vulnerability = vulnerability
            return True
        return False

    def remove_vulnerability(self, defence:Defence|str) -> bool:
        """
        Remove a vulnerability from a specific defence. 

        Args:
            defence (Defence | str): A cyber security defence mechanism, such as a firewall.

        Returns:
            bool: Whether the vulnerability was successfully removed from the defence
        """
        name = defence.name if isinstance(defence, Defence) else defence
        if name in self.defences:
            self.defences[name].remove_vulnerability()
            return True
        return False
