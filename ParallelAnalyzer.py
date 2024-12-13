import time, copy
import logging, warnings
import csv, json, yaml
import math, random
import numpy as np
import argparse
import pandapower
import tqdm
import multiprocessing as mp
from multiprocessing import Process, Queue, current_process, freeze_support
from communication.network import CommNetwork
from cyber.analysis import Analyzer
from attackers.interface import Attacker
from attackers.random_attacker import RandomAttacker
from communication.components import Device
from cyber.criticality import criticality_by_degree, criticality_by_power_flow, criticality_by_capacity
from pathlib import Path


import inspect, warnings, random
import numpy as np
import pandapower
import tqdm
import ray
from pathlib import Path
from ray.util.queue import Queue
from dataclasses import dataclass
from attackers.interface import Attacker
from attackers.random_attacker import RandomAttacker
from communication.network import CommNetwork
from communication.components import Device
from cyber.criticality import criticality_by_capacity

def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return 1
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return 0
    else:
        raise ValueError(f"invalid truth value {val!r}")

@dataclass
class AttackerConfig:
    budget:float 
    auto_compromise_children:bool = False
    verbose:bool = False
    
@dataclass
class MonteSample:
    attack_idx:int
    entrypoint_idx:int
    param_idx:int
    n_compromised:int
    total_effort_spent:float
    critical_sum:float = 0.0

@ray.remote
class MonteOverseer():
    
    def __init__(self, n_entrypoints:int, n_attacks_per_entrypoint:int,
                 n_params:int, queue:Queue):
        self.fill_level = 0
        self.fill_limit = n_entrypoints*n_attacks_per_entrypoint
        self.compromised = np.zeros((n_attacks_per_entrypoint, n_entrypoints, n_params), dtype=np.int32)
        self.effort = np.zeros((n_attacks_per_entrypoint, n_entrypoints, n_params), dtype=np.float32)
        self.criticality = np.zeros((n_attacks_per_entrypoint, n_entrypoints, n_params), dtype=np.float32)
        self.queue = queue
        
    def get(self):
        return (self.compromised, self.effort, self.criticality)
    
    def run(self):
        while True:
            sample:MonteSample = self.queue.get(block=True)
            
            # Put sample into pre-allocated arrays
            i, j, v = sample.attack_idx, sample.entrypoint_idx, sample.param_idx
            self.compromised[i, j, v] = sample.n_compromised
            self.effort[i, j, v] = sample.total_effort_spent
            self.criticality[i, j, v] = sample.critical_sum
            
            self.fill_level += 1
            # Finished processing all tasks
            if self.fill_level == self.fill_limit:
                break
        logging.info("Overseer :: Finished Monte Carlo simulation")

@ray.remote(num_cpus=1)
class MonteActor():
    
    """
    Each Monte Actor runs in its own Python process.
    """
    
    def __init__(self, actor_id:int, queue:Queue, global_seed:int,
                 attacker_class:Attacker,
                 attacker_config:AttackerConfig, 
                 param:str = "", param_values:list = [],
                 device_only:bool=True,
                 random_entry:bool=True,
                 report_freq:int=1000,
                 **network_kwargs):
        self.actor_id = actor_id
        self.i = 0
        self.queue = queue
        # NOTE: Each time the network is initialized, the effort and success prob. is fixed
        # Need to reset these each time to ensure we get different numbers when compromising
        # it again
        self.global_seed = global_seed
        self.param = param.strip()
        self.param_values = param_values
        self.network_kwargs = network_kwargs
        np.random.seed(self.global_seed)
        # Use many networks, but only create each once
        if self.param != "" and self.param in self.network_kwargs: 
            self.network_kwargs[self.param] = param_values[0]
            self.network = {param_values[0]: CommNetwork(**network_kwargs)}
        else: # Only use 1 network throughout
            self.network = CommNetwork(**network_kwargs)
        self.attacker_class = attacker_class
        self.attacker_kwargs = attacker_config.__dict__
        self.attacker = self.attacker_class(**self.attacker_kwargs)
        self.device_only = device_only
        self.random_entry = random_entry
        self.report_freq = report_freq
        
    def work(self, idx:int, seed:int, entrypoint:int, param_idx:int):
        # >> Select Communication Network <<
        param_value = self.param_values[param_idx]
        if self.param == "" or self.param not in self.network_kwargs:
            network = self.network
        elif param_value in self.network:
            network = self.network[network]
        else: # Haven't seen this configuration before
            np.random.seed(self.global_seed)
            self.network_kwargs[self.param] = param_value
            network = CommNetwork(**self.network_kwargs)
            self.network[param_value] = network
        # Parameter of Attacker can also be varied
        if self.param in self.attacker_kwargs:
            attacker = self.attacker_class(**self.attacker_kwargs)
        else:
            attacker = self.attacker
        
        # >> Reset & set entrypoint for cyberattacks <<
        np.random.seed(seed)
        network.reset(entrypoint)
        
        nodes_compromised, total_effort_spent = attacker.attack_network(network)
        # Count how many nodes were compromised (and add up their criticality)
        critical_sum, device_count = 0, 0
        for n in nodes_compromised:
            if isinstance(n, Device):
                critical_sum += n.equipment.criticality if n.equipment is not None else 0
                device_count += 1
        
        # Package results as a MonteSample dataclass
        n_compromised = device_count if self.device_only else len(nodes_compromised)
        sample = MonteSample(attack_idx=idx,
                             entrypoint_idx=0 if self.random_entry else entrypoint,
                             param_idx=param_idx,
                             n_compromised=n_compromised,
                             total_effort_spent=total_effort_spent, 
                             critical_sum=critical_sum)
        
        # Asynchronously publish results to queue
        self.queue.put_nowait(sample)
        
        self.i += 1
        if self.i % self.report_freq == 0:
            logging.info(f"Actor {self.actor_id} :: Samples Completed {self.i}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='ParallelAnalyzer',
                    description='Monte Carlo Cyber Attack Simulation',
                    epilog='--- End of Help ---')
    parser.add_argument('-N', "--N", '--n_attacks',  dest="N", type=int,
                        nargs='?', default=10000, help='Number of attacks')
    parser.add_argument('-T', '--threads',  dest="threads", type=int,
                        nargs='?', default=4, help='Number of parallel threads')
    parser.add_argument('--seed',  dest="global_seed", type=int,
                        nargs='?', default=0, help='Global Seed (note: reproducibility not gauranteed, use archived data)')
    parser.add_argument('-D', '--devices', dest="n_devices", type=int,
                        nargs='?', default=20, help='No. of Devices')
    parser.add_argument("--per", "--per-parent", "--child-per-parent", "--children-per-parent", dest="children_per_parent", 
                        default=3, nargs="?", type=int,
                        help="Average number of children per parent")
    parser.add_argument("--dev", "--deviation", "--child-no-deviation", dest="child_no_deviation",
                        default=0, nargs="?", type=int,
                        help="Random variation about the avg. number of children")
    parser.add_argument("-v", "--values", dest="param_values", nargs="+",
                        help="Values of parameter", type=float,
                        default=[52])
    parser.add_argument('-B', '--budget', dest="budget", type=float,
                        nargs='?', default=52.0, help='Size of attacker budget')
    parser.add_argument('-E', '--vary_entrypoints', dest="vary_entrypoints", type=lambda x:bool(strtobool(x)),
                        nargs='?', default=True, help='Whether to vary the entrypoints')
    parser.add_argument('-R', '--random_entry', dest="random_entry", type=lambda x:bool(strtobool(x)),
                        nargs='?', default=False, help='Randomize entrypoint')
    parser.add_argument('--auto', dest="auto_compromise_children", type=lambda x:bool(strtobool(x)),
                        nargs='?', default=False, help='Whether to automatically compromise children')
    parser.add_argument('--device_only', dest="device_only", type=lambda x:bool(strtobool(x)),
                        nargs='?', default=False, help='Whether to only enter at devices')
    parser.add_argument("--param", dest="param_name", type=str, default="budget", 
                        help="Which parameter to vary")
    parser.add_argument("--savename", "--name", dest="save_name", nargs="?",
                        help="Name of file to save to", type=str,
                        default="ParallelMonte")
    parser.add_argument("--crit", "--criticality", dest="criticality", default="", nargs="?", type=str,
                        help="One of 'capacity', 'powerflow', or 'degree', '' (None)")
    parser.add_argument('-S', '--sibling_to_sibling_comm', dest="sibling_to_sibling_comm", type=str,
                        nargs='?', default="all", help="Type of connection between siblings ['all', 'adjacent', 'False']")
    parser.add_argument('-M', '--network_specs', dest="network_specs", type=str,
                        nargs='?', default="default", help="Network specifications")
    parser.add_argument('-G', '--grid', dest="grid", type=str,
                    nargs='?', default="create_cigre_network_mv", help="Type of physical grid to load")
    args = parser.parse_args()
    
    np.random.seed(args.global_seed)
    
    kwargs = {}
    for name, arg in vars(args).items():
        if name == "criticality":
            if arg.strip() != "":
                arg = {"degree":criticality_by_degree, "powerflow":criticality_by_power_flow,
                       "capacity":criticality_by_capacity}[arg.strip().lower()]
        elif name == "grid":
            if arg == "real":
                arg = Path.cwd() / "data" / "SpanishLVNetwork" / "RunDss" / "grid.json"
            kwargs["grid_kwargs"] = {"with_der":"all"} if arg == "create_cigre_network_mv" else {}
        if name != args.param_name:
            kwargs[name] = arg
    
    if not ray.is_initialized():
        ray.init()
    n_cpu = max(1, int(ray.available_resources().get("CPU", 1)) - 1)
    
    # >> Load Physical Grid <<
    with (open(Path.cwd() / "data" / "SpanishLVNetwork" / "RunDss" / "grid.json") as f,
          warnings.catch_warnings(category=FutureWarning, action="ignore")):
        real_grid = pandapower.from_json(f)
    grid_map = {name:creator for name, creator in inspect.getmembers(pandapower.networks, predicate=inspect.isfunction)}
    grid_map.update({"real":real_grid, "cigre":pandapower.networks.cigre_networks.create_cigre_network_mv})
    with warnings.catch_warnings():
        warnings.filterwarnings(action="ignore", category=FutureWarning)
        if type(kwargs["grid"]) is str:
            grid = grid_map.get(kwargs["grid"])(**kwargs["grid_kwargs"])
        elif type(kwargs["grid"]) is Path:
            grid = pandapower.from_json(kwargs["grid"])
        else:
            grid = None # No physical grid
    
    # >> Set Communication Network Parameters <<
    criticality = kwargs["criticality"](grid, verbose=False)[0] if (kwargs["criticality"] != "" and grid is not None) else None
    spec_path = Path.cwd() / "specifications" / f"{args.network_specs.capitalize()}_specifications.json"
    network_kwargs = dict(
        n_devices = kwargs.get("n_devices", 20), # Only affects comm. network topology if Grid is None
        children_per_parent = kwargs.get("children_per_parent", 3), # No. of children per aggregator
        child_no_deviation = kwargs.get("child_no_deviation", 0), # Random variation in children per aggregator
        sibling_to_sibling_comm = kwargs.get("sibling_to_sibling_comm", "all"),
        grid = grid, # Selects which physical grid comm. network will oversee
        network_specs = spec_path, # Specifies comm. network component types / defeneses
        criticality = criticality,
        crit_norm = False,
        effort_only = False,
        n_entrypoints = 1,
    )
    network = CommNetwork(**network_kwargs)
    
    # >> Store Metadata <<
    if args.param_name.strip() != "":
        save_dir = Path.cwd() / "data" / "results" / args.param_name / args.save_name
    else:
        save_dir = Path.cwd() / "data" / "results" / "FixedParams" / args.save_name
    save_dir.mkdir(exist_ok=True, parents=True)
    with open(save_dir / f"{args.save_name}_metadata.yaml", "w") as f:
        yaml.dump({**args.__dict__,**kwargs}, f)
    
    # >> Initialize Ray Actors <<
    task_queue = Queue()
    N_ATTACKS = args.N
    # NOTE: Varying entrypoint is NOT compatible with varying the network structure
    N_ENTRYPOINTS = network.n_components if args.vary_entrypoints and not args.random_entry else 1
    N_PARAMS = len(kwargs["param_values"])
    overseer = MonteOverseer.remote(N_ENTRYPOINTS, N_ATTACKS, N_PARAMS, task_queue)
    attacker_config = AttackerConfig(budget=kwargs.get("budget", 52.0),
                                     auto_compromise_children=kwargs.get("auto_compromise_children", False),
                                     verbose=False)
    
    workers = [MonteActor.remote(actor_id, task_queue, kwargs["global_seed"], RandomAttacker, attacker_config, 
                                 param=kwargs["param_name"], param_values=kwargs["param_values"],
                                 device_only=args.device_only, random_entry=args.random_entry,
                                **network_kwargs) for actor_id in range(n_cpu-1)]
    overseer.run.remote()
    
    # >> Queue Tasks for Ray Actors <<
    pos = 0
    idcs = range(N_ATTACKS)
    seeds = np.random.choice(N_ATTACKS, size=N_ATTACKS, replace=False)
    entrypoints = np.arange(N_ENTRYPOINTS)
    
    print(f"Total Number of Tasks: {N_ATTACKS*N_ENTRYPOINTS*N_PARAMS}")
    
    print("Starting Monte Carlo Simulations")
    start_time = time.time()
    for param_idx in tqdm.tqdm(range(N_PARAMS), desc="Param ::", total=N_PARAMS, position=0):
        for entrypoint_idx in tqdm.tqdm(entrypoints, desc="Entrypoint :: ", total=N_ENTRYPOINTS, position=1):
            for attack_idx, seed in tqdm.tqdm(zip(idcs, seeds), desc="Iteration ::", total=N_ATTACKS, position=2):
                if args.random_entry: # Randomly choose an entrypoint
                    entrypoint_idx = np.random.choice(network.n_components)
                workers[pos % len(workers)].work.remote(attack_idx, int(seed), entrypoint_idx, param_idx)
                pos += 1
    print("Finished Sending Monte Carlo Tasks")
    
    # >> Fetch results <<
    compromised, effort, criticality = ray.get(overseer.get.remote())
    duration = time.time() - start_time
    
    # >> Archive Results to Disk <<
    print("Writing Archive to File ...")
    np.savez(save_dir / f"{kwargs['save_name']}.npz",
             compromise=compromised,
             effort=effort,
             criticality=criticality)
    print("Finished Writing Archive to File")
    
    # >> Save Time Profiling <<
    with open(save_dir / f"{args.save_name}_ComputeTime.yaml", "w") as f:
        yaml.dump({"n_cpu":n_cpu, "total time taken (s)": duration, 
                   "n_attacks": N_ATTACKS, "n_entrypoints":N_ENTRYPOINTS, "n_params":N_PARAMS,
                   "time / sample (s)": duration/(N_ATTACKS*N_ENTRYPOINTS*N_PARAMS),
                   "time / entrypoint (s)": duration/(N_ENTRYPOINTS*N_PARAMS),
                   "time / param (s)": duration/(N_PARAMS)}, f)
    
    analyzer = Analyzer(network)
    print(compromised.shape, effort.shape, criticality.shape, (N_ATTACKS, N_ENTRYPOINTS, N_PARAMS))
    analyzer.res_monte = {**{"compromised":compromised, "effort":effort, "criticality":criticality},
                          **({"param_name":args.param_name, "param_values":args.param_values})}
    analyzer.plot_monte(save_name=args.save_name, save_dir=save_dir,
                        figsize=((14, 16) if not math.isclose(np.mean(criticality), 0) else (14,12)),
                        flatten=True)