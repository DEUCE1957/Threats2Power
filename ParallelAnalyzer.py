import time, copy
import inspect, warnings, random
import logging
import csv, json, yaml
import math, random
import numpy as np
import argparse
import pandapower
import tqdm
import ray
from pathlib import Path
from dataclasses import dataclass
from ray.util.queue import Queue
from ray.experimental.tqdm_ray import tqdm
from threats2power.communication import Device, CommNetwork
from threats2power.cyber import (Analyzer, criticality_by_degree, 
                                 criticality_by_power_flow, criticality_by_capacity)
from threats2power.attackers import Attacker, RandomAttacker

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
    repeated_attacks:bool = False
    
@dataclass
class MonteSample:
    attack_idx:int
    entrypoint_idx:int
    param_idx:int
    n_compromised:int
    total_effort_spent:float
    critical_sum:float = 0.0

@ray.remote(num_cpus=1, max_restarts=1)
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
                 random_param:bool=False,
                 report_freq:int=1000, 
                 **network_kwargs):
        self.actor_id:int = actor_id
        self.i:int = 0
        self.queue:Queue = queue
        # NOTE: Each time the network is initialized, the effort and success prob. is fixed
        # Need to reset these each time to ensure we get different numbers when compromising
        # it again
        self.global_seed:int = global_seed
        self.param:str = param.strip()
        self.param_values:list = param_values
        self.min_param, self.max_param = min(param_values), max(param_values)
        self.network_kwargs:dict = network_kwargs
        np.random.seed(self.global_seed)
        # Use many networks, but only create each once
        if self.param != "" and self.param in self.network_kwargs: 
            self.network_kwargs[self.param] = param_values[0]
            self.network_lookup:dict = {param_values[0]: CommNetwork(**network_kwargs)}
        else: # Only use 1 network throughout
            self.network_lookup:CommNetwork = CommNetwork(**network_kwargs)
        self.attacker_class:Attacker = attacker_class
        self.attacker_kwargs:dict = attacker_config.__dict__
        self.attacker:Attacker = self.attacker_class(**self.attacker_kwargs)
        self.device_only:bool = device_only
        self.random_entry:bool = random_entry
        self.random_param:bool = random_param
        self.report_freq:int = report_freq
        print(f"Monte Actor {actor_id} | Global Seed {global_seed} | Param '{self.param}' | Attacker {self.attacker_class.__name__}")
    
    def work(self, idx:int, seed:int, entrypoint:int, param_idx:int):
        # >> Select Communication Network <<
        if param_idx == -1: # Randomly choose a parameter
            param_value = np.random.uniform(self.min_param, self.max_param)
            param_idx = 0
        else:
            param_value = self.param_values[param_idx]
        if self.param == "" or self.param not in self.network_kwargs:
            network = self.network_lookup
        elif param_value in self.network_lookup:
            network = self.network_lookup[network]
        else: # Haven't seen this configuration before
            np.random.seed(self.global_seed)
            self.network_kwargs[self.param] = param_value
            network = CommNetwork(**self.network_kwargs)
            self.network_lookup[param_value] = network
        # Parameter of Attacker can also be varied
        if self.param in self.attacker_kwargs:
            self.attacker_kwargs[self.param] = param_value
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
                             param_idx=0 if self.random_param else param_idx,
                             n_compromised=n_compromised,
                             total_effort_spent=total_effort_spent, 
                             critical_sum=critical_sum)
        
        # Asynchronously publish results to queue
        self.queue.put_nowait(sample)
        
        self.i += 1
        if self.i == 1 or self.i % self.report_freq == 0:
            print(f"Actor {self.actor_id} :: Samples Completed {self.i} :: Param '{self.param}':{param_value} [{param_idx}] :: Seed {seed} :: Entrypoint {entrypoint}")
            
        return True

class MonteScheduler():
    
    def __init__(self, workers:list[ray.ObjectRef], params:list, n_entrypoints:int, n_attacks:int,
                 random_entry:bool=False, random_param:bool=False,
                 task_limit:int=1000):
        self.n_workers = len(workers)
        self.n_params = 1 if random_param else len(params)
        self.n_entrypoints = 1 if random_entry else n_entrypoints
        self.random_entry = random_entry
        self.random_param = random_param
        self.min_param, self.max_param = min(params), max(params)
        self.n_attacks = n_attacks
        self.total_tasks = self.n_params*self.n_entrypoints*self.n_attacks
        self.attack_idcs = range(self.n_attacks)
        self.seeds = np.random.choice(self.n_attacks, size=self.n_attacks, replace=False)
        
        self.pos = 0
        self.position = {"param_idx":0, "entrypoint_idx":0, "attack_idx":0}
        self.tasks = []
        self.task_limit = task_limit
    
        self.no_of_tasks_queued = 0
        
    def schedule(self):
        print(f"Scheduler: Scheduling {self.total_tasks} new tasks")
        
        # stop_early = False
        for param_idx in tqdm(range(self.n_params),
                            desc="Param ::", total=self.n_params, position=0):
            for entrypoint_idx in tqdm(range(self.n_entrypoints),
                                    desc="Entrypoint :: ", total=self.n_entrypoints, position=1):
                for attack_idx, seed in tqdm(zip(range(self.n_attacks), 
                                                self.seeds[self.position["attack_idx"]:]), 
                                            desc="Iteration ::", total=self.n_attacks, position=2):
                    if self.random_entry: # Randomly choose an entrypoint
                        entrypoint_idx = np.random.choice(self.n_entrypoints)
                    if self.random_param: # Randomly choose a parameter vale
                        param_idx = -1
                    self.tasks.append(workers[self.pos % self.n_workers].work.remote(attack_idx, int(seed), entrypoint_idx, param_idx))
                    self.pos += 1
                    
                    # Wait for tasks to finish before continuing
                    if len(self.tasks) > self.task_limit:
                        ready_refs, self.tasks = ray.wait(self.tasks, num_returns=1)
                        ray.get(ready_refs)
        print(f"Finished Scheduling {self.pos} Tasks")

@ray.remote
class MonteOverseer():
    
    def __init__(self, n_entrypoints:int, n_attacks_per_entrypoint:int, 
                 n_params:int, queue:Queue, save_dir:Path,
                 report_freq:int=1000):
        self.fill_level = 0
        self.fill_limit = n_entrypoints*n_attacks_per_entrypoint*n_params
        self.compromised = np.zeros((n_attacks_per_entrypoint, n_entrypoints, n_params), dtype=np.int32)
        self.effort = np.zeros((n_attacks_per_entrypoint, n_entrypoints, n_params), dtype=np.float32)
        self.criticality = np.zeros((n_attacks_per_entrypoint, n_entrypoints, n_params), dtype=np.float32)
        self.queue:Queue = queue
        self.save_dir = save_dir
        self.report_freq = report_freq
        
    def get(self):
        return (self.compromised, self.effort, self.criticality)
    
    def run(self):
        for _ in tqdm(range(self.fill_limit+1)):
            sample:MonteSample = self.queue.get(block=True)
            
            # Put sample into pre-allocated arrays
            i, j, v = sample.attack_idx, sample.entrypoint_idx, sample.param_idx
            self.compromised[i, j, v] = sample.n_compromised
            self.effort[i, j, v] = sample.total_effort_spent
            self.criticality[i, j, v] = sample.critical_sum
            
            self.fill_level += 1
            
            if self.fill_level % self.report_freq == 0:
                print(f"Overseer :: Fill Level {self.fill_level}/{self.fill_limit} ({100.0*(self.fill_level/self.fill_limit):.4f}%)")
                (i, j, v, sample.n_compromised, sample.total_effort_spent, sample.critical_sum)
            # Finished processing all tasks
            if self.fill_level == self.fill_limit:
                break
        print("Overseer :: Finished Monte Carlo simulation")
        return (self.compromised, self.effort, self.criticality)
    
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
    parser.add_argument('--repeat_attacks', '--repeated_attacks', dest="repeated_attacks", type=lambda x:bool(strtobool(x)),
                        nargs='?', default=True, help='Whether to allow repeated attacks if initial comproise is unsuccessful')
    parser.add_argument('-R', '--random_entry', dest="random_entry", type=lambda x:bool(strtobool(x)),
                        nargs='?', default=False, help='Randomize entrypoint')
    parser.add_argument('--random_param', dest="random_param", type=lambda x:bool(strtobool(x)),
                        nargs='?', default=False, help='Randomize parameters within range, only works for non-network parameters')
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
    parser.add_argument('-i', "--interactive", dest="interactive", type=lambda x:bool(strtobool(x)),
                        nargs='?', default=True, help='Whether to prompt user for choices')
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
            kwargs["grid_kwargs"] = {"with_der":"all"} if arg in ["cigre", "create_cigre_network_mv"] else {}
        if name != args.param_name:
            kwargs[name] = arg
    
    if not ray.is_initialized():
        ray.init(log_to_driver=True)
    n_cpu = max(1, int(ray.available_resources().get("CPU", 1)) - 1)
    
    # >> Load Physical Grid <<
    grid_map = {name:creator for name, creator in inspect.getmembers(pandapower.networks, predicate=inspect.isfunction)}
    grid_map.update({"cigre":pandapower.networks.cigre_networks.create_cigre_network_mv})
    with warnings.catch_warnings():
        warnings.filterwarnings(action="ignore", category=FutureWarning)
        if type(kwargs["grid"]) is str:
            grid = grid_map.get(kwargs["grid"])(**kwargs["grid_kwargs"])
        elif isinstance(kwargs["grid"], Path):
            grid = pandapower.from_json(kwargs["grid"])
        else:
            print("Warning: No grid loaded, criticality is ignored")
            grid = None # No physical grid
    # >> Set Communication Network Parameters <<
    if kwargs["criticality"] != "" and grid is not None:
        criticality_map, _, _ = kwargs["criticality"](grid, verbose=False)
    else:
        criticality_map = None
    spec_path = Path.cwd() / "specifications" / f"{args.network_specs.capitalize()}_specifications.json"
    network_kwargs = dict(
        n_devices = kwargs.get("n_devices", 20), # Only affects comm. network topology if Grid is None
        children_per_parent = kwargs.get("children_per_parent", 3), # No. of children per aggregator
        child_no_deviation = kwargs.get("child_no_deviation", 0), # Random variation in children per aggregator
        sibling_to_sibling_comm = kwargs.get("sibling_to_sibling_comm", "all"),
        grid = grid, # Selects which physical grid comm. network will oversee
        network_specs = spec_path, # Specifies comm. network component types / defeneses
        criticality = criticality_map,
        crit_norm = False,
        effort_only = False,
        n_entrypoints = 1,
    )
    if args.param_name in network_kwargs and args.random_param:
        raise ValueError(f"Parameter '{args.param_name}' is a network parameter, which cannot be randomly varied.")
    network = CommNetwork(**network_kwargs)
    
    # >> Store Metadata <<
    if args.param_name.strip() != "":
        save_dir = Path.cwd() / "data" / "results" / args.param_name / args.save_name
    else:
        save_dir = Path.cwd() / "data" / "results" / "FixedParams" / args.save_name
        
    load_previous = False
    if save_dir.exists() and args.interactive:
        while (resp := input("Run Monte ('run') or Load Previous ('load')?").strip().lower()) not in ('run', 'load'):
            continue
        if resp == 'load':
            load_previous = True
        
    if not load_previous:
        save_dir.mkdir(exist_ok=True, parents=True)
        with open(save_dir / f"{args.save_name}_metadata.yaml", "w") as f:
            yaml.dump({**args.__dict__,**kwargs}, f)
        
        # >> Initialize Ray Actors <<
        task_queue = Queue()
        N_ATTACKS = args.N
        # NOTE: Varying entrypoint is NOT compatible with varying the network structure
        N_ENTRYPOINTS = network.n_components if args.vary_entrypoints and not args.random_entry else 1
        N_PARAMS = 1 if args.random_param else len(kwargs["param_values"])
        
        # Overseer will store results, and periodically prompt the scheduler to add more tasks
        overseer = MonteOverseer.remote(N_ENTRYPOINTS, N_ATTACKS, N_PARAMS, task_queue, save_dir)
        
        attacker_config = AttackerConfig(budget=kwargs.get("budget", 52.0),
                                         auto_compromise_children=kwargs.get("auto_compromise_children", False),
                                         repeated_attacks=kwargs.get("repeated_attacks", False),
                                         verbose=False)
        
        workers = [MonteActor.remote(actor_id, task_queue, kwargs["global_seed"], RandomAttacker, attacker_config, 
                                     param=kwargs["param_name"], param_values=kwargs["param_values"],
                                     device_only=args.device_only, random_entry=args.random_entry,
                                     random_param=args.random_param,
                                     **network_kwargs) for actor_id in range(n_cpu-1)]
        
        
        print("Starting Monte Carlo Simulations")
        print(f"Total Number of Tasks: {N_ATTACKS*N_ENTRYPOINTS*N_PARAMS}")
        start_time = time.time()
        # Scheduler will Queue tasks for Ray ActorsR
        scheduler = MonteScheduler(workers, kwargs["param_values"], N_ENTRYPOINTS, N_ATTACKS, 
                                   random_entry=args.random_entry, random_param=args.random_param,
                                   task_limit=1000)
        scheduler.schedule()
        # >> Fetch results <<
        compromised, effort, criticality = ray.get(overseer.run.remote())
        duration = time.time() - start_time
    
        # >> Archive Results to Disk <<
        print("Writing archive to file ...")
        np.savez(save_dir / f"{kwargs['save_name']}.npz",
                compromise=compromised,
                effort=effort,
                criticality=criticality)
        print("Finished writing archive to file")
        
        # >> Save Time Profiling <<
        with open(save_dir / f"{args.save_name}_ComputeTime.yaml", "w") as f:
            yaml.dump({"n_cpu":n_cpu, "total time taken (s)": duration, 
                    "n_attacks": N_ATTACKS, "n_entrypoints":N_ENTRYPOINTS, "n_params":N_PARAMS,
                    "time / sample (s)": duration/(N_ATTACKS*N_ENTRYPOINTS*N_PARAMS),
                    "time / entrypoint (s)": duration/(N_ENTRYPOINTS*N_PARAMS),
                    "time / param (s)": duration/(N_PARAMS)}, f)
    else: # Load Previous
        print("Reading archive from file ...")
        arrays = np.load(save_dir / f"{kwargs['save_name']}.npz")
        compromised = arrays.get("compromise", None)
        effort = arrays.get("effort", None)
        criticality = arrays.get("criticality", None)
        print("Finished reading archive from file")
    
    analyzer = Analyzer(network)
    for name, array in zip(["Compromised", "Effort", "Criticality"], [compromised, effort, criticality]):
        print(f"{name} array :: Min {array.min():.4f} :: Max {array.max():.4f} :: Mean {array.mean():.4f} :: Shape {array.shape}")
    analyzer.res_monte = {**{"compromised":compromised, "effort":effort, "criticality":criticality},
                          **({"param_name":args.param_name, "param_values":args.param_values})}
    fig_height = 16 - (4 if math.isclose(np.mean(criticality), 0) else 0) - (4 if math.isclose(np.mean(effort), np.max(effort)) else 0)
    analyzer.plot_monte(save_name=args.save_name, save_dir=save_dir,
                        figsize=(14,fig_height),
                        max_criticality=network.maximum_criticality,
                        random_param=args.random_param,
                        flatten=True)