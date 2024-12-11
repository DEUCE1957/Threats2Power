import copy
import math
import numpy as np
import pandas as pd
import arviz as az
from fractions import Fraction
import multiprocess as mp
import matplotlib as mpl
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from tqdm import tqdm
from scipy import stats
from communication.components import Device
from communication.network import CommNetwork
from attackers.interface import Attacker
from attackers.random_attacker import RandomAttacker

def mean_confidence_interval(data, confidence=0.95):
    a = 1.0 * np.array(data)
    n = len(a)
    m, se = np.mean(a), stats.sem(a)
    h = se * stats.t.ppf((1 + confidence) / 2., n-1)
    return m, m-h, m+h


def iterate_over_paths(path, prob, success_count, reachable_nodes={}, visited_nodes={}, id_to_node={}):
    current_id = path[-1]
    current_node = id_to_node[current_id]
    visited_previously = current_id in visited_nodes
    if not visited_previously:
        visited_nodes[current_id] = None
    
    neighbouring_nodes = {k.id:None for k in current_node.get_neighbours()}
    failed_reach = copy.copy(reachable_nodes)
    failed_reach = {k:None for k in failed_reach if k not in visited_nodes}

    reachable_nodes.update(neighbouring_nodes)
    reachable_nodes = {k:None for k in reachable_nodes if k not in visited_nodes}
    
    success_prob = current_node.get_prob_to_compromise()
    if visited_previously:
        return
    n_reachable = len(reachable_nodes)
    # Success
    for reachable_node_id in  list(reachable_nodes.keys()):
        yield from iterate_over_paths(path+[reachable_node_id], prob*success_prob*(1/n_reachable), success_count + 1,
                                    copy.copy(reachable_nodes), copy.copy(visited_nodes),
                                    id_to_node=id_to_node)
    if len(reachable_nodes) == 0:
        yield path, prob*success_prob, False, success_count + 1

    # Failure
    n_reachable = len(failed_reach)
    for reachable_node_id in list(failed_reach.keys()):
        yield from iterate_over_paths(path+[reachable_node_id], prob*(1-success_prob)*(1/n_reachable), success_count,
                                    failed_reach, copy.copy(visited_nodes),
                                    id_to_node=id_to_node)
    if len(failed_reach) == 0:
        yield path, prob*(1-success_prob), True, success_count

def get_all_paths(graph):
    n_nodes = len(graph.nodes())
    id_to_node = {node.id:node for node in graph.nodes()}
    start_ids = list(id_to_node.keys())
    # Different starting locations
    for start_node_id in start_ids:
        yield from iterate_over_paths([start_node_id], prob=1/n_nodes, success_count=0,
                                    reachable_nodes={}, visited_nodes={},
                                    id_to_node=id_to_node)

def monte_process(process_idx, seed, n_attacks=1000, budget=52,
                  vary_entrypoints=False, device_entry_only=False, auto_compromise_children:bool=False, **network_kwargs):
    import numpy as np
    from communication.network import CommNetwork
    from attackers.random_attacker import RandomAttacker
    
    # Procedurally generate a communication network with specific redundancy
    np.random.seed(seed)
    pcn = CommNetwork(**network_kwargs)

    analyzer = Analyzer(pcn)

    compromised_array, effort_array, critical_array = analyzer.monte_carlo_analysis(n_attacks, budget, 
                                                                                    vary_entrypoints=vary_entrypoints,
                                                                                    auto_compromise_children=auto_compromise_children,
                                                                                    **network_kwargs)
    return process_idx, compromised_array, effort_array, critical_array

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
        res_static = {i:0 for i in range(self.network.n_components+1)}
        for path_no, (path, prob, ends_on_failure, success_count) in tqdm(enumerate(get_all_paths(self.network.graph)), desc="Path ", leave=False):
            # path_length = len(path) - 1 if ends_on_failure else len(path)
            if show_paths:
                print(f"Path {path_no} :: Prob {str(Fraction(prob).limit_denominator()):<15}" + 
                        f" :: {'-'.join([str(node) for node in path])} :: {'F' if ends_on_failure else 'S'} :: {success_count}")
            res_static[success_count] += prob
            sum_probs += prob
        if verbose:
            print(f"No. of Paths: {path_no}. Sum of Probabilities: {sum_probs} ({Fraction(sum_probs).limit_denominator()})")
        if verbose:
            print("\n".join(f"{k} devices: {v}" for k,v in sorted(res_static.items(),key=lambda item: item[0])))
        return res_static
    
    def monte_carlo_analysis(self, n_attacks:int, budget:float, attacker_variant:Attacker=RandomAttacker,
                             device_only:bool=True, vary_entrypoints:bool=False, auto_compromise_children:bool=False, 
                             **kwargs):
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
        # Set Entrypoints
        original_entrypoints = [n.id for n in self.network.entrypoints]
        if vary_entrypoints: # 1 entrypoint per device
            entrypoints = [n for n in self.network.node_ids if (isinstance(self.network.id_to_node[n], Device) if device_only else True)]
        else:
            entrypoints = original_entrypoints

        # Either use all components as an entrypoint, or the existing entrypoints
        n_entrypoints = len(entrypoints)
        self.res_monte["compromised"] = np.zeros(shape=(n_attacks, n_entrypoints), dtype=np.int16)
        self.res_monte["effort"] = np.zeros(shape=(n_attacks, n_entrypoints), dtype=np.float32)
        self.res_monte["criticality"] = np.zeros(shape=(n_attacks, n_entrypoints), dtype=np.float32)

        self.res_monte.update(dict(attacker_variant=attacker_variant, budget=budget, n_attacks=n_attacks,
                                   n_entrypoints=n_entrypoints, auto_compromise_children=auto_compromise_children))

        for i, entrypoint_id in tqdm(enumerate(entrypoints), desc="Entrypoint "): 
            # Consider attacks eminating from specific entrypoint
            self.network.set_entrypoints(entrypoint_id)
            for attack_no in tqdm(range(n_attacks), desc="Attack "):
                attacker = attacker_variant(budget=budget, auto_compromise_children=auto_compromise_children, verbose=False)
                nodes_compromised, total_effort_spent = attacker.attack_network(self.network)
                # Count how many nodes were compromised (and add up their criticality)
                critical_sum, device_count = 0, 0
                for n in nodes_compromised:
                    if isinstance(n, Device):
                        critical_sum += n.equipment.criticality if n.equipment is not None else 0
                        device_count += 1
                self.res_monte["compromised"][attack_no, i] = device_count if device_only else len(nodes_compromised)
                self.res_monte["effort"][attack_no, i] = total_effort_spent
                self.res_monte["criticality"][attack_no, i] = critical_sum
                self.network.reset(entrypoint_id)
        self.network.reset(original_entrypoints)
        return self.res_monte["compromised"], self.res_monte["effort"], self.res_monte["criticality"]
    
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
        n_jobs = len(param_values) if param_name != "n_attacks" else 1
        n_processes = min(mp.cpu_count() - 2, n_jobs)
        
        vary_entrypoints = kwargs.get("vary_entrypoints", False)
        n_entrypoints = self.network.n_devices if vary_entrypoints else kwargs.get("n_entrypoints", 1)

        self.res_monte["compromised"] = np.zeros(shape=(n_samples, n_entrypoints, n_jobs), dtype=np.int16)
        self.res_monte["effort"] = np.zeros(shape=(n_samples, n_entrypoints, n_jobs), dtype=np.float32)
        self.res_monte["criticality"] = np.zeros(shape=(n_samples, n_entrypoints, n_jobs), dtype=np.float32)
        self.res_monte.update(dict(param_name=param_name, param_values=param_values))
        print(f"CPU Count: {n_processes}, Jobs: {n_jobs}")

        with mp.Pool(processes=n_processes) as pool, tqdm(total=n_jobs) as pbar:
            results = []
            for i, value in enumerate(param_values):
                print(f"{param_name.replace('_',' ').capitalize()}: {value}")
                kwds = {**{param_name:value}, **kwargs}
                results.append(
                    pool.apply_async(monte_process, args=[i, seed], callback=lambda _:pbar.update(1), kwds=kwds)
                )
            for result in results:
                job_idx, compromises, efforts, criticality = result.get()
                self.res_monte["compromised"][:, :, job_idx] = compromises
                self.res_monte["effort"][:, :, job_idx] = efforts
                self.res_monte["criticality"][:, :, job_idx] = criticality
        return self.res_monte["compromised"], self.res_monte["effort"], self.res_monte["criticality"]

    def plot_monte(self, info:bool=False, palette:str="Dark2", save_name="Monte",
                   save_dir:Path=Path(__file__).parent.parent / "media",
                   figsize=(14,12), bin_widths:list[float]=[1.0, 5.0], flatten:bool=False):
        sns.set_context('paper', font_scale=2.0)
        if self.res_monte != {}:
            # Multiple Monte Carlo Processes
            if "param_values" in self.res_monte:
                # Reshape to collapse all entrypoint variations into the first dimension
                n_attacks, n_entrypoints, n_params = self.res_monte["compromised"].shape
                self.res_monte["compromised"] = np.reshape(self.res_monte["compromised"], (n_attacks*n_entrypoints, n_params))
                # Create Pandas Dataframe (to name attributes)
                df = pd.DataFrame(self.res_monte["compromised"], columns=self.res_monte["param_values"])
                df = df.melt(var_name=self.res_monte["param_name"])

                fig, ax = plt.subplots(nrows=1, ncols=1, figsize=figsize)
                sns.set_context(font_scale=2.0)
                sns.histplot(df, x="value", hue=self.res_monte["param_name"], discrete=True, stat="probability", common_norm=False, ax=ax)
                sns.move_legend(ax, "upper right", ncols=4, title=" ".join([word.capitalize() for word in self.res_monte["param_name"].split("_")]))
                ax.set(xlabel="No. of Devices Compromised", yscale="log")
                fig.savefig(save_dir / f"{save_name}.pdf")
                plt.show()
            # Single Monte Carlo Process
            else:
                if info:
                    print(f"Attacker: {self.res_monte['attacker_variant'].__name__}, Budget: {self.res_monte['budget']}\n" + 
                          f"Network Size: {self.network.n_components}, No. of Devices: {self.network.n_devices}, " + 
                          f"No. of Entrypoints: {self.network.n_entrypoints}")
                                # Combine all entrypoints if Flatten is True
                compromised = self.res_monte["compromised"].flatten() if flatten else self.res_monte["compromised"]
                effort = self.res_monte["effort"].flatten() if flatten else self.res_monte["effort"]
                criticality = self.res_monte["criticality"].flatten() if flatten else self.res_monte["criticality"]

                has_varied_entrypoints = False if flatten else (True if compromised.shape[1] > 1 else False)
                has_criticality = True if not math.isclose(criticality.mean(), 0) else False

                fig = plt.figure(figsize=figsize)
                gs = mpl.gridspec.GridSpec(nrows=3 if has_criticality else 2, ncols=2, figure=fig, width_ratios=(0.95, 0.05))

                N = 1 if flatten else compromised.shape[1]
                palette = sns.color_palette(palette=palette, n_colors=N, as_cmap=False)
                hue_settings = dict(palette=palette) if N > 1 else {}
                cmap = mpl.colors.ListedColormap(palette)

                # Compromise Distribution
                ax = fig.add_subplot(gs[0, 0] if has_varied_entrypoints else gs[0, :])
                sns.histplot(compromised, discrete=True, stat="probability", ax=ax, **hue_settings)
                ax.set(xlabel="No. of Components Compromised", xlim=(-0.5, np.max(compromised)+0.5))
                
                legend = ax.get_legend()
                if legend is not None:
                    legend.remove()

                # Effort Distribution
                ax = fig.add_subplot(gs[1, 0] if has_varied_entrypoints else gs[1, :])
                sns.histplot(effort, binwidth=1, stat="percent", ax=ax, **hue_settings)
                ax.set(xlabel="Effort Spent", xlim=(0, np.max(effort)))
                
                legend = ax.get_legend()
                if legend is not None:
                    legend.remove()
                
                # Criticality Distribution
                if has_criticality:
                    print(f"Susceptibility Index: {np.mean(criticality)} (Max: {self.network.maximum_criticality})")
                    ax = fig.add_subplot(gs[2, 0] if has_varied_entrypoints else gs[2, :])
                    max_criticality = self.network.maximum_criticality if max_criticality is None else max_criticality
                    for i, binwidth in enumerate(bin_widths):
                        sns.histplot(criticality, binwidth=binwidth, binrange=(0, max_criticality), stat="probability",
                                     label=f"Bin Width: {binwidth:.1f}", zorder=-i, ax=ax, **hue_settings)
                    mean, low, high = mean_confidence_interval(criticality, confidence=0.95)
                    ax.vlines(x=[mean], ymin=0, ymax=ax.get_ylim()[1], label="Mean", zorder=1,
                                color="red", linestyles="--", linewidth=3)
                    
                    print("Mean Confidence Interval: ", low, mean, high)
                    print("High Credibility Interval: ", az.hdi(criticality))
                    # ax.axvspan(low, high, alpha=0.5, color='red')
                    ax.axvspan(*az.hdi(criticality), alpha=0.5, color='red', zorder=-10)
                    ax.legend()
                    ax.set(xlabel="Criticality", yscale="log")
                    plt.show()
                    

                if has_varied_entrypoints:
                    norm = mpl.colors.BoundaryNorm(np.linspace(0, N, N+1), cmap.N)
                    sm = mpl.cm.ScalarMappable(cmap=cmap, norm=norm)
                    fig.colorbar(sm, cax=fig.asdd_subplot(gs[:, 1]), label="Entrypoint",
                                    ticks=np.arange(1, N+1))
                plt.tight_layout()
                fig.savefig(save_dir / f"{save_name}.pdf")
                plt.show()

                
                
    
    def plot_static(self):
        if self.res_static != {}:
            fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(8,6))
            sns.barplot(self.res_static, ax=ax)
            ax.set(ylabel="Probability", xlabel="Components")

            fig.suptitle(f"Network Size: {self.network.n_components}, No. of Devices: {self.network.n_devices}, " + 
                        f"No. of Entrypoints: {self.network.n_entrypoints}", 
                                        y=-0.01, fontsize="medium", ma="center")