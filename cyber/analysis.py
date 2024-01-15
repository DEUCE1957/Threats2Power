import copy
import numpy as np
import pandas as pd
from fractions import Fraction
import multiprocess as mp
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm
from communication.components import Device
from communication.network import CommNetwork
from attackers.interface import Attacker
from attackers.random_attacker import RandomAttacker
# TODO: Account for probability of 0 devices being compromised

def iterate_over_paths(path, prob, reachable_nodes={}, visited_nodes={}, id_to_node={}):
    current_id = path[-1]
    current_node = id_to_node[current_id]
    visited_previously = current_id in visited_nodes
    if not visited_previously:
        visited_nodes[current_id] = None
    
    neighbouring_nodes = {k.id:None for k in current_node.get_neighbours()}
    reachable_nodes.update(neighbouring_nodes)
    reachable_nodes = {k:None for k in reachable_nodes if k not in visited_nodes}
    success_prob = current_node.get_prob_to_compromise()
    # If we fail, this path terminates
    yield path, prob*(1-success_prob), True
    if visited_previously:
        return
    n_reachable = len(reachable_nodes)
    reachable_ids =  list(reachable_nodes.keys())
    for reachable_node_id in reachable_ids:
        yield from iterate_over_paths(path+[reachable_node_id], prob*success_prob*(1/n_reachable),
                                    copy.copy(reachable_nodes), copy.copy(visited_nodes),
                                    id_to_node=id_to_node)
        
    # No more nodes reachable (entire network compromised)
    if len(reachable_nodes) == 0:
        yield path, prob*success_prob, False

def get_all_paths(graph):
    n_nodes = len(graph.nodes())
    id_to_node = {node.id:node for node in graph.nodes()}
    start_ids = list(id_to_node.keys())
    # Different starting locations
    for start_node_id in start_ids:
        yield from iterate_over_paths([start_node_id], prob=1/n_nodes,
                                    reachable_nodes={}, visited_nodes={},
                                    id_to_node=id_to_node)

def monte_process(process_idx, seed, n_attacks=1000, budget=52, **network_kwargs):
    import numpy as np
    from communication.network import CommNetwork
    from attackers.random_attacker import RandomAttacker
    
    # Procedurally generate a communication network with specific redundancy
    np.random.seed(seed)
    pcn = CommNetwork(**network_kwargs)

    analyzer = Analyzer(pcn)

    compromised_array, effort_array = analyzer.monte_carlo_analysis(n_attacks, budget, **network_kwargs)
    return process_idx, compromised_array, effort_array

class Analyzer():

    def __init__(self, network:CommNetwork) -> None:
        """
        Args:
            network (CommNetwork): A communication network with nodes and edges
        """
        self.network = network
        self.res_static = {}
        self.res_monte = {}

    def static_analysis(self, verbose:bool=True, show_paths:bool=False):
        """
        Add up the probability of compromising N devices for each possible path through the 
        network. Since the number of paths increases exponentially with network size, static
        analysis is only computationally tractable for small networks.
        Beware that since probabilities are between 0.0 and 1.0, longer paths can lead to
        floating point precision errors.

        Args:
            verbose (bool): Whether to print out summary information
            show_paths (bool): Whether to print out each path (can be very long for larger networks)
        """
        sum_probs = 0.0
        self.res_static = {}
        for path_no, (path, prob, ends_on_failure) in tqdm(enumerate(get_all_paths(self.network.graph)), desc="Path ", leave=False):
            if show_paths:
                print(f"Path {path_no} :: Prob {str(Fraction(prob).limit_denominator()):<15}" + 
                        f" :: {'-'.join([str(node) for node in path])} :: {ends_on_failure}")
            # if (len(path) > 1 and ends_on_failure) or (not ends_on_failure):
            path_length = len(path) - 1 if ends_on_failure else len(path)
            self.res_static[path_length] = prob if path_length not in self.res_static else self.res_static[path_length] + prob
            sum_probs += prob
        if verbose:
            print(f"No. of Paths: {path_no}. Sum of Probabilities: {sum_probs} ({Fraction(sum_probs).limit_denominator()})")
        if verbose:
            print("\n".join(f"{k} devices: {v}" for k,v in sorted(self.res_static.items(),key=lambda item: item[0])))
        return self.res_static
    
    def monte_carlo_analysis(self, n_attacks:int, budget:float, attacker_variant:Attacker=RandomAttacker,
                             device_only:bool=True, **kwargs):
        """
        Approximate the true probability of compromising N devices by running many randomly
        varying attacks on the same communication network. The approximation becomes more
        accurate as the number of simulated attacks increases. 

        Args:
            n_attacks (int): Number of attacks to simulate
            budget (float): Number of effective workdays attacker has to compromise assets. 
                A higher number corresponds to a more sophisticated attacker (more time and/or resources available)
            attacker_variant (Attacker): Strategy employed by the attacker.
                Defaults to RandomAttacker.
            device_only (bool): Whether to only count compromised devices (leaf nodes) in the total tally.
                Defaults to True.
        """
        self.res_monte["compromised"] = np.zeros(shape=n_attacks, dtype=np.int16)
        self.res_monte["effort"] = np.zeros(shape=n_attacks, dtype=np.float32)
        self.res_monte.update(dict(attacker_variant=attacker_variant, budget=budget, n_attacks=n_attacks))
        for attack_no in tqdm(range(n_attacks), desc="Attack "):
            attacker = attacker_variant(budget=budget, verbose=False)
            nodes_compromised, total_effort_spent = attacker.attack_network(self.network)
            self.res_monte["compromised"][attack_no] = len([n for n in nodes_compromised if \
                                                (isinstance(n, Device) if device_only else True)])
            self.res_monte["effort"][attack_no] = total_effort_spent
            self.network.reset()
        return self.res_monte["compromised"], self.res_monte["effort"]
    
    def monte_carlo_multi_analysis(self, seed:int, param_name:str, param_values, **kwargs):
        """
        Approximate the true probability of compromising N devices over variations of a
        communication network. The approximation becomes more accurate as the number of
        simulated attacks increases. This allows one parameter to be varied, to see the 
        effect it has on the overall security of the communication network type.

        Args:
            seed (int): Random seed to use inside each process.
            param_name (str): Name of parameter that is varied.
            param_values (iterable): Values that the parameter can take.
        """
        print(f"Seed: {seed}")
        np.random.seed(seed)

        n_samples = kwargs.get("n_attacks", 1000) if param_name != "n_attacks" else max(param_values)
        n_processes = len(param_values) if param_name != "n_attacks" else 1
        self.res_monte["compromised"] = np.zeros(shape=(n_samples, n_processes), dtype=np.int16)
        self.res_monte["effort"] = np.zeros(shape=(n_samples, n_processes), dtype=np.float32)
        self.res_monte.update(dict(param_name=param_name, param_values=param_values))
        print(f"CPU Thread Count: {mp.cpu_count()-2}")

        with mp.Pool(processes=len(param_values)) as pool:
            results = []
            for i, value in enumerate(param_values):
                print(f"{param_name.replace('_',' ').capitalize()}: {value}")
                kwds = {**{param_name:value}, **kwargs}
                results.append(
                    pool.apply_async(monte_process, args=[i, seed], kwds=kwds)
                )
            
            for result in results:
                process_idx, compromises, efforts = result.get()
                self.res_monte["compromised"][:, process_idx] = compromises
                self.res_monte["effort"][:, process_idx] = efforts
        return self.res_monte["compromised"], self.res_monte["effort"]
    
    def plot_monte(self):
        if self.res_monte != {}:
            # Single Monte Carlo Process
            if self.res_monte["compromised"].ndim == 1:
                fig, axes = plt.subplots(nrows=2, ncols=1, figsize=(8,6))
                fig.suptitle(f"Attacker: {self.res_monte['attacker_variant'].__name__}, Budget: {self.res_monte['budget']}\n" + 
                               f"Network Size: {self.network.n_components}, No. of Devices: {self.network.n_devices}, " + 
                               f"No. of Entrypoints: {self.network.n_entrypoints}", 
                            y=-0.05, fontsize="medium", ma="center")
                sns.histplot(self.res_monte["compromised"], discrete=True, stat="probability", ax=axes[0])
                axes[0].set(xticks=np.arange(0, len(self.network.graph.nodes())), xlabel="No. of Devices Compromised")
                sns.histplot(self.res_monte["effort"], binwidth=1, ax=axes[1])
                axes[1].set(xlabel="Effort Spent")
                plt.tight_layout()
                plt.show()
            # Multiple Monte Carlo Processes
            else:
                df = pd.DataFrame(self.res_monte["compromised"], columns=self.res_monte["param_values"])
                df = df.melt(var_name=self.res_monte["param_name"])

                # display(df)
                fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(8,6))
                sns.histplot(df, x="value", hue=self.res_monte["param_name"], discrete=True, stat="probability", common_norm=False, ax=ax)
                sns.move_legend(ax, "upper right", ncols=4, title=self.res_monte["param_name"])
                ax.set(xlabel="No. of Devices Compromised")
                plt.show()
    
    def plot_static(self):
        if self.res_static != {}:
            fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(8,6))
            sns.barplot(self.res_static, ax=ax)
            ax.set(ylabel="Probability", xlabel="Devices")

            fig.suptitle(f"Network Size: {self.network.n_components}, No. of Devices: {self.network.n_devices}, " + 
                        f"No. of Entrypoints: {self.network.n_entrypoints}", 
                                        y=-0.01, fontsize="medium", ma="center")