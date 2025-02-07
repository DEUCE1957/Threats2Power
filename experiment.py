import argparse
import math
import warnings
import math
import time
import numpy as np
import pandas as pd
import pandapower
import inspect
import yaml
import matplotlib.pyplot as plt
from IPython.display import display
from ipywidgets import Button, HBox, VBox
from pathlib import Path

from communication.network import CommNetwork
from cyber.analysis import Analyzer
from attackers.random_attacker import RandomAttacker

def is_interactive():
    try:
        shell = get_ipython().__class__.__name__
        if shell == 'ZMQInteractiveShell':
            return True   # Jupyter notebook or qtconsole
        elif shell == 'TerminalInteractiveShell':
            return False  # Terminal running IPython
        else:
            return False  # Other type (?)
    except NameError:
        return False      # Probably standard Python interpreter

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

def run_experiment(seed:int=0, spec:str="Default", grid:str|Path="create_cigre_network_mv", grid_kwargs:dict={},
                   criticality=None, save_name:str|None=None,
                   param_name:str="children_per_parent",
                   param_values:list=[2, 3, 5, 8, 13, 21, 34, lambda network: network.n_devices],
                   n_attacks:int=1000, flatten:bool=False, auto_compromise_children:bool=False, 
                   out_dir:Path=Path.cwd() / "data", **kwargs):
    np.random.seed(seed)
    print(f"Seed: {seed}")

    if param_name == "n_devices" and grid is not None:
        raise ValueError(f"Grid should be undefined for device count to be set.")
    grid_map = {name:creator for name, creator in inspect.getmembers(pandapower.networks, predicate=inspect.isfunction)}
    with warnings.catch_warnings():
        warnings.filterwarnings(action="ignore", category=FutureWarning)
        if type(grid) is str:
            grid = grid_map.get(grid)(**grid_kwargs) if grid is not None else None
        else:
            grid = pandapower.from_json(grid)
        criticality = criticality(grid, verbose=False)[0] if criticality is not None else criticality
        spec_path = Path.cwd() / "specifications" / f"{spec.capitalize()}_specifications.json"
        network = CommNetwork(n_devices=kwargs.get("n_devices", 20),
                              n_entrypoints=kwargs.get("n_entrypoints", 1),
                              child_no_deviation=kwargs.get("child_no_deviation", 0),
                              children_per_parent=kwargs.get("children_per_parent", 3),
                              sibling_to_sibling_comm=kwargs.get("sibling_to_sibling_comm", None),
                              repeated_attacks=kwargs.get("repeated_attacks", False),
                              criticality=criticality,
                              network_specs=spec_path, grid=grid)
    print(f"Number of Components: {network.n_components}")

    # Total number of attacks: no_of_components * N_ATTACKS
    param_values = [val(network) if inspect.isfunction(val) else val for val in param_values]
    analyzer = Analyzer(network)
    exp_desc = '_'.join([w.capitalize() for w in param_name.split('_')])
    kwarg_desc = '-'.join(f"{k}_{v}" for k,v in kwargs.items())
    save_name = save_name if save_name is not None else f"{exp_desc}" + (f"--{kwarg_desc}" if kwarg_desc else "")
    archive_path = out_dir / f"{save_name}.npz"
    print(f"Archive Path: '{archive_path}'")

    def run_monte(event):
        print("Running New Monte Carlo Simulation (Estimated Time to Completion: 40 minutes)")
        if len(param_values) > 1:
            monte_kwargs = dict(seed=seed,
                                n_attacks=n_attacks,
                                child_no_deviation=kwargs.get("child_no_deviation", 0),
                                auto_compromise_children=auto_compromise_children,
                                grid=grid,
                                vary_entrypoints=kwargs.get("vary_entrypoints", True),
                                effort_only=kwargs.get("effort_only", False),
                                criticality=criticality,
                                repeated_attacks=kwargs.get("repeated_attacks", False),
                                param_name=param_name, param_values=param_values)
            
            compromised_array, effort_array, criticality_array = analyzer.monte_carlo_multi_analysis(**monte_kwargs)
        else:
            monte_kwargs = dict(
                n_attacks=n_attacks, attacker_variant=RandomAttacker,
                budget=kwargs.get("budget",52), device_only=False, 
                sibling_to_sibling_comm=kwargs.get("sibling_to_sibling_comm", None),
                vary_entrypoints=kwargs.get("vary_entrypoints", True),
                auto_compromise_children=auto_compromise_children,
                repeated_attacks=kwargs.get("repeated_attacks", False),)
            compromised_array, effort_array, criticality_array = analyzer.monte_carlo_analysis(**monte_kwargs)
        np.savez(archive_path, compromise=compromised_array, effort=effort_array, criticality=criticality_array) # .flatten()
        analyzer.plot_monte(save_name=save_name, save_dir=out_dir,
                            figsize=((14, 16) if not math.isclose(np.mean(criticality_array), 0) else (14,12)),
                            flatten=flatten)

    def load_previous(event):
        print("Loading Previous Session")
        arrays = np.load(archive_path)
        print(arrays.keys())
        compromised_array = arrays.get("compromise")
        effort_array = arrays.get("effort")
        criticality_array = arrays.get("criticality", np.zeros_like(compromised_array))
        analyzer.res_monte = {**{"compromised":compromised_array, "effort":effort_array, "criticality":criticality_array},
                              **({} if len(param_values) == 1 else {"param_name":param_name, "param_values":param_values})}
        analyzer.plot_monte(save_name=save_name, save_dir=out_dir,
                            figsize=(14, 16) if "criticality" in arrays else (14,12), flatten=flatten,
                            **kwargs)

    if is_interactive():
        run_button = Button(description="Run Monte", button_style="info", style=dict(font_size="Large"), continuous_update=False)
        run_button.on_click(run_monte)
        load_button = Button(description="Load Previous", button_style="info", style=dict(font_size="Large"), continuous_update=False,
                             disabled=False if archive_path.exists() else True)
        load_button.on_click(load_previous)
        box = HBox([run_button, load_button])
        display(box)
    elif archive_path.exists():
        while (resp := input("Run Monte ('run') or Load Previous ('load')?").strip().lower()) not in ('run', 'load'):
            continue
        if resp == 'run':
            run_monte(None)
        elif resp == 'load':
            load_previous(None)
    else:
        print("Running Monte Carlo Simulation")
        run_monte(None)
        
if __name__ == "__main__":
    from cyber.criticality import criticality_by_degree, criticality_by_power_flow, criticality_by_capacity
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", default=0, nargs="?", type=int,
                        help="Seed for Monte Carlo simulation")
    parser.add_argument("-N", "--N", dest="n_attacks", default=10000, nargs="?", type=int,
                        help="Number of attacks / Monte Carlo simultions")
    parser.add_argument("--crit", "--criticality", dest="criticality", default=None, nargs="?", type=str,
                        help="One of 'capacity', 'powerflow', or 'degree'")
    parser.add_argument("--spec", default="Default", nargs="?", type=str,
                        help="Which specification file to use")
    parser.add_argument("--grid", default="create_cigre_network_mv", nargs="?", type=str,
                        help="Which physical grid to load")
    parser.add_argument("-p", "--param", dest="param_name", type=str, default="budget", 
                        help="Which parameter to vary")
    parser.add_argument("-v", "--values", dest="param_values", nargs="+",
                        help="Values of parameter", type=float,
                        default=[52])
    parser.add_argument("--savename", "--name", dest="save_name", nargs="?",
                        help="Name of file to save to", type=str,
                        default="Susceptibility")
    parser.add_argument("--vary", "--vary-entrypoints", 
                        dest="vary_entrypoints", type=lambda x:bool(strtobool(x)),
                        default=True, help="Whether to vary the entrypoints")
    parser.add_argument("--flatten", 
                        dest="flatten", type=lambda x:bool(strtobool(x)),
                        default=True, help="Whether to flatten the output")
    parser.add_argument("--budget", dest="budget", 
                        default=52, nargs="?", type=int,
                        help="Number of effective work days available to attacker")
    parser.add_argument("--sib", "--sibling-to-sibling-comm", dest="sibling_to_sibling_comm", 
                        default="all", nargs="?", type=str,
                        help="Type of connection between siblings")
    parser.add_argument("--per", "--per-parent", "--child-per-parent", "--children-per-parent", dest="children_per_parent", 
                        default=3, nargs="?", type=int,
                        help="Average number of children per parent")
    parser.add_argument("--dev", "--deviation", "--child-no-deviation", dest="child_no_deviation",
                        default=0, nargs="?", type=int,
                        help="Random variation about the avg. number of children")
    args = parser.parse_args()

    kwargs = {}
    for name, arg in vars(args).items():
        if name == "criticality":
            if arg is not None:
                arg = {"degree":criticality_by_degree, "powerflow":criticality_by_power_flow,
                       "capacity":criticality_by_capacity}[arg.strip().lower()]
        elif name == "grid":
            if arg == "real":
                arg = Path.cwd() / "data" / "SpanishLVNetwork" / "RunDss" / "grid.json"
            kwargs["grid_kwargs"] = {"with_der":"all"} if arg == "create_cigre_network_mv" else {}
        if name != args.param_name:
            kwargs[name] = arg
    print(kwargs)
    save_dir = Path.cwd() / "data" / "results" / kwargs["param_name"] / kwargs["save_name"]
    save_dir.mkdir(exist_ok=True, parents=True)
    with open(save_dir / f"{kwargs.get('save_name')}_metadata.yaml", "w") as f:
        yaml.dump(kwargs, f)
    
    start = time.time()
    run_experiment(out_dir=save_dir,
                   **kwargs)
    duration = time.time() - start
    with open(save_dir / f"{kwargs.get('save_name')}.info", "w") as f:
        f.writelines([f"duration (seconds):{duration}\n",
                      f"time per entrypoint (seconds): {duration / kwargs['n_attacks']}\n"])
    