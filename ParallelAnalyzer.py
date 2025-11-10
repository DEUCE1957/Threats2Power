import time
import csv
import json
import random
import math
import warnings
import numpy as np
import argparse
import pandapower
import tqdm
import multiprocessing as mp
from multiprocessing import Process, Queue, current_process, freeze_support
from threats2power.communication.network import CommNetwork
from threats2power.cyber.analysis import Analyzer
from threats2power.attackers.interface import Attacker
from threats2power.attackers.random_attacker import RandomAttacker
from threats2power.communication.components import Device
from threats2power.cyber.criticality import criticality_by_degree, criticality_by_power_flow, criticality_by_capacity
from pathlib import Path
# attack_seeds = np.random.randint(low=0, high=2**32-1, size=n_attacks)
# Each thread grabs work from the queue (seed for network)
# Each thread builds internal list of results
# mp.JoinableQueue()

# Function run by worker processes
def worker(input:Queue, output:Queue, device_only:bool=False, budget:float=52.0,
           auto_compromise_children:bool=False, attacker_variant:Attacker=RandomAttacker, **network_kwargs):
    
    network = CommNetwork(**network_kwargs)
    analyzer = Analyzer(network)
    attacker = attacker_variant(budget=budget, auto_compromise_children=auto_compromise_children, verbose=False)

    for args in tqdm.tqdm(iter(input.get, 'STOP'), desc=f"Worker {mp.current_process().name}"):
        seed, entrypoint_id = args
        # print(f"Entrypoint: {entrypoint_id}, Seed: {seed}")
        np.random.seed(seed)
        analyzer.network.set_entrypoints(entrypoint_id)
        attacker.budget = budget

        critical_sum, device_count = 0, 0
        nodes_compromised, total_effort_spent = attacker.attack_network(analyzer.network)

        # Count how many nodes were compromised (and add up their criticality)
        critical_sum, device_count = 0, 0
        for n in nodes_compromised:
            if isinstance(n, Device):
                critical_sum += n.equipment.criticality if n.equipment is not None else 0
                device_count += 1
        
        output.put((entrypoint_id, device_count if device_only else len(nodes_compromised), total_effort_spent, critical_sum))
        analyzer.network.reset(entrypoint_id)
    print(f"Worker {mp.current_process().name} Finished")

def data_collector(output:Queue, n_attacks:int, n_entrypoints:int, save_name="ParallelMonte",
                   budget:float=52.0, auto_compromise_children:bool=False, attacker_variant:Attacker=RandomAttacker,
                   flatten:bool=False, **network_kwargs):
    # network = CommNetwork(**network_kwargs)
    # analyzer = Analyzer(network)
    # Either use all components as an entrypoint, or the existing entrypoints
    # res_monte = {"compromised": np.zeros(shape=(n_attacks, n_entrypoints), dtype=np.int16),
    #              "effort":np.zeros(shape=(n_attacks, n_entrypoints), dtype=np.float32),
    #              "criticality":np.zeros(shape=(n_attacks, n_entrypoints), dtype=np.float32)}
    # res_monte.update(dict(attacker_variant=attacker_variant, budget=budget, n_attacks=n_attacks,
    #                             n_entrypoints=n_entrypoints, auto_compromise_children=auto_compromise_children))
    
    with open(Path.cwd() / "data" / "ParallelMonte.csv", "w", newline='') as f:
        writer = csv.writer(f, delimiter=";", )
        writer.writerow(["attack_no", "entrypoint_id", "n_compromised", "effort_spent", "critical_sum"])
        # f.writelines([f"attack_no;entrypoint_id;n_compromised;effort_spent;critical_sum\n"])
        for i in tqdm.trange(n_attacks*n_entrypoints, desc="Collector"):
            attack_no = i % n_attacks
            entrypoint_id, n_compromised, effort_spent, critical_sum = output.get(block=True)
            # res_monte["compromised"][attack_no, entrypoint_id] = n_compromised
            # res_monte["effort"][attack_no, entrypoint_id] = effort_spent
            # res_monte["criticality"][attack_no, entrypoint_id] = critical_sum
            writer.writerow([attack_no, entrypoint_id, n_compromised, effort_spent, critical_sum])

    # archive_path = Path.cwd() / "data" / "ParallelMonte.npz"
    # np.savez(archive_path, compromise=res_monte["compromised"], effort=res_monte["effort"], criticality=res_monte["criticality"])
    # print("Plotting")
    # analyzer.res_monte = res_monte
    # analyzer.plot_monte(save_name=save_name, figsize=((14, 16) if not math.isclose(np.mean(res_monte["criticality"]), 0) else (14,12)), flatten=flatten)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='ParallelAnalyzer',
                    description='Monte Carlo Cyber Attack Simulation',
                    epilog='--- End of Help ---')
    parser.add_argument('-N', '--n_attacks',  metavar='N', dest="n_attacks", type=int,
                        nargs='?', default=10000, help='Number of attacks')
    parser.add_argument('-T', '--threads',  dest="threads", type=int,
                        nargs='?', default=4, help='Number of parallel threads')
    parser.add_argument('-E', '--vary_entrypoints', dest="vary_entrypoints", type=bool,
                        nargs='?', default=True, help='Whether to vary the entrypoints')
    parser.add_argument('-R', '--random_entry', dest="random_entry", type=bool,
                        nargs='?', default=True, help='Randomize entrypoint')
    parser.add_argument('-K', '--criticality', dest="use_criticality", type=bool,
                        nargs='?', default=True, help='Whether to enable criticality calculations.')
    parser.add_argument('-B', '--budget', dest="budget", type=float,
                        nargs='?', default=52.0, help='Size of attacker budget')
    parser.add_argument('--device_only', dest="device_only", type=bool,
                        nargs='?', default=False, help='Whether to only enter at devices')
    parser.add_argument('-D', '--devices', dest="n_devices", type=int,
                        nargs='?', default=20, help='No. of Devices')
    parser.add_argument('-C', '--children_per_parent', dest="children_per_parent", type=int,
                        nargs='?', default=2, help='Avg. No. of children per aggregator / parent')
    parser.add_argument('-P', '--child_no_deviation', dest="child_no_deviation", type=int,
                        nargs='?', default=0, help='Deviation in no. of children per aggregator / parent.')
    parser.add_argument('-S', '--sibling_to_sibling_comm', dest="sibling_to_sibling_comm", type=str,
                        nargs='?', default="all", help="Type of connection between siblings ['all', 'adjacent', 'False']")
    parser.add_argument('-M', '--network_specs', dest="network_specs", type=str,
                        nargs='?', default="default", help="Network specifications")
    
    args = parser.parse_args()
    with (open(Path.cwd() / "data" / "SpanishLVNetwork" / "RunDss" / "grid.json") as f,
          warnings.catch_warnings(category=FutureWarning, action="ignore")):
        grid = pandapower.from_json(f)
    sibling_to_sibling_comm = False if args.sibling_to_sibling_comm.strip().lower() == "false" else True
    criticality = criticality_by_capacity(grid, verbose=False)[0] if args.use_criticality else None
    kwargs = dict(device_only=args.device_only, budget=args.budget,
                  n_devices=args.n_devices, children_per_parent=args.children_per_parent,
                  child_no_deviation=args.child_no_deviation,
                  sibling_to_sibling_comm=sibling_to_sibling_comm, grid=grid,
                  spec_path = Path.cwd() / "specifications" / f"{args.network_specs.capitalize()}_specifications.json",
                  criticality=criticality)
    network = CommNetwork(**kwargs)
    print(f"Network: {network.n_components} (Components), {network.n_devices} (N Devices)")
    # total_no_of_attacks = args.n_attacks * (network.n_components if args.vary_entrypoints else 1)
    seeds = np.random.choice(args.n_attacks, size=args.n_attacks, replace=False)

    with open(Path.cwd() / "data" / "ParallelMonteSettings.json", "w") as f:
        json.dump(args.__dict__, f)
    # Set Entrypoints
    # original_entrypoints = [n.id for n in network.entrypoints]
    # if args.vary_entrypoints: # 1 entrypoint per device
    # else:
    #     entrypoints = original_entrypoints
    entrypoints = [n for n in network.node_ids if (isinstance(network.id_to_node[n], Device) if args.device_only else True)]
    if args.random_entry:
        entrypoints = np.random.choice(entrypoints, size=args.n_attacks, replace=True)
    else:
        entrypoints = list(entrypoints[len(entrypoints)//2:(len(entrypoints)//2)+2])
    print(f"Entrypoints: {entrypoints}")

    print("Initializing Queues")
    task_queue = Queue()
    if args.random_entry:
        for seed, entrypoint_id in zip(seeds, entrypoints):
            task_queue.put((seed, entrypoint_id))
    else:
        for entrypoint_id in entrypoints:
            for seed in seeds:
                task_queue.put((seed, entrypoint_id))
        
    output_queue = Queue()
    print("Starting Processes")
    for i in range(args.threads):
        Process(target=worker, args=(task_queue, output_queue), kwargs=kwargs).start()
    Process(target=data_collector, args=(output_queue, args.n_attacks, 1 if args.random_entry else len(entrypoints))).start()
    
    for i in range(args.threads):
        task_queue.put('STOP')
    print("Finished Monte Carlo simulation")