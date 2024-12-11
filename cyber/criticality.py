import math
import numpy as np
import pandas as pd
import pandapower
import networkx as nx
from collections import defaultdict


def criticality_by_degree(grid:pandapower.pandapowerNet, degree=nx.degree, verbose:bool=False):
    """
    Determines the criticality of power grid components based on their
    degree in a graph representation of the grid. By default this is 
    the number of edges going into or out of the bus, or the bus the
    equipment is attached to.

    Args:
        grid (pandapower.pandapowerNet): Power grid representation in PandaPower
        degree (function): Accepts Networkx graph as input and returns the degree of the node
        verbose (bool): Whether to print additional information.
            Defaults to False.
    Returns:
        dict<str:np.ndarray>: 1D array containing criticality values per PandaPower element type
        float: Lowest criticality value encountered 
        float: Highest criticality value encountered
    """
    criticality = {}
    bus_to_connection = defaultdict(list)
    for line_idx, (from_bus, to_bus) in grid.line.loc[:, ["from_bus", "to_bus"]].iterrows():
        bus_to_connection[from_bus].append(f"line_{line_idx}")
        bus_to_connection[to_bus].append(f"line_{line_idx}")
    for dcline_idx, (from_bus, to_bus) in grid.dcline.loc[:, ["from_bus", "to_bus"]].iterrows():
        bus_to_connection[from_bus].append(f"dcline_{dcline_idx}")
        bus_to_connection[to_bus].append(f"dcline_{dcline_idx}")
    for trafo_idx, (from_bus, to_bus) in grid.trafo.loc[:, ["hv_bus", "lv_bus"]].iterrows():
        bus_to_connection[from_bus].append(f"trafo_{trafo_idx}")
        bus_to_connection[to_bus].append(f"trafo_{trafo_idx}")
    bus_to_degree = {bus_no:len(lines) for bus_no, lines in bus_to_connection.items()}
    degree = np.array([value for _, value in sorted(bus_to_degree.items(), key=lambda x:x[0])])
    lowest, highest = math.inf, -math.inf
    for kind in pandapower.pp_elements():
        df = getattr(grid, kind)
        if kind == "bus":
            criticality["bus"] = degree
        elif hasattr(df, "bus"): # Load / Generator
            criticality[kind] = getattr(df, "bus").map(bus_to_degree)
        elif hasattr(df, "from_bus"): # Line
            criticality[kind] = getattr(df, "from_bus").map(bus_to_degree).add(getattr(df, "to_bus").map(bus_to_degree))
        elif hasattr(df, "hv_bus"): # Transformer
            criticality[kind] = getattr(df, "hv_bus").map(bus_to_degree).add(getattr(df, "lv_bus").map(bus_to_degree))
        else:
            criticality[kind] = np.zeros(df.shape[0])
        if df.shape[0] > 0:
            low = np.min(criticality[kind])
            lowest = low if low < lowest else lowest
            high = np.max(criticality[kind])
            highest = high if high > highest else highest
    return criticality, lowest, highest

def criticality_by_power_flow(grid:pandapower.pandapowerNet, verbose:bool=False):
    """
    Determines the criticality of each component based on the apparent power flow. Requires a single
    power flow to be performed first. The apparent power is used as a proxy for criticality. Since it
    is based on a power flow, it only holds for that particular state of the power grid.
    It is assumed that greater apparent power corresponds to greater criticality. 

    Args:
        grid (pandapower.pandapowerNet): Power grid with valid parameters defined to perform power flow simulation.
        verbose (bool): Whether to print additional information.
            Defaults to False.

    Returns:
        dict<str:np.ndarray>: 1D array containing criticality values per PandaPower element type
        float: Lowest criticality value encountered 
        float: Highest criticality value encountered
    """
    criticality = {}
    if grid.res_bus.shape[0] == 0:
        if verbose: print("Running Power Flow")
        pandapower.runpp(grid, algorithm="nr", calculate_voltage_angles=True, init="dc", trafo_model="t", trafo_loading="power",
                        enforce_q_lims=True, voltage_depend_loads=True, numba=True, consider_line_temperature=False)

    def get_apparent_power(grid, attr):
        df = getattr(grid, f"res_{attr}") if hasattr(grid, f"res_{attr}") else getattr(grid, attr)
        if "p_mw" in df.columns:
            active_power = df.loc[:, "p_mw"]
            reactive_power =  df.loc[:, "q_mvar"]
            apparent_power = np.sqrt(np.power(active_power, 2) + np.power(reactive_power, 2))
        elif attr == "switch":
            apparent_power = np.zeros(grid.switch.shape[0])
            apparent_line_power = get_apparent_power(grid, "line")
            apparent_trafo_power = get_apparent_power(grid, "trafo")
            for idx, row in grid.switch.iterrows():
                if row.et == "l": # Line
                    apparent_power[idx] = apparent_line_power[row.element]
                elif row.et == "t": # Transformer
                    apparent_power[idx] = apparent_trafo_power[row.element]
        elif attr in ["measurement", "trafo3w"]:
            if verbose: print(f"'{attr}' apparent power calculation not supported")
            apparent_power = pd.Series([])
        else:
            start = "hv" if "trafo" in attr else "from"
            end = "lv" if "trafo" in attr else "to"
            active_power = np.max(np.abs(df.loc[:, [f"p_{start}_mw", f"p_{end}_mw"]]), axis=1)
            reactive_power = np.max(np.abs(df.loc[:, [f"q_{start}_mvar", f"q_{end}_mvar"]]), axis=1)
            apparent_power = np.sqrt(np.power(active_power, 2) + np.power(reactive_power, 2))
        return apparent_power

    lowest, highest = math.inf, -math.inf
    for attr in pandapower.pp_elements():
        apparent_power = get_apparent_power(grid, attr)
        low, high = np.min(apparent_power), np.max(apparent_power)
        lowest = low if low < lowest else lowest
        highest = high if high > highest else highest
        criticality[attr] = apparent_power
    return criticality, lowest, highest

def criticality_by_capacity(grid, verbose:bool=False):
    """
    Determines the criticality of each component based on the maximum theoretical apparent 
    power that can be generated, consumed or transferred by the component. Buses inherit
    the apparent power from all connecting elements.

    Args:
        grid (pandapower.pandapowerNet): Power grid with valid parameters defined to perform power flow simulation.
        verbose (bool): Whether to print additional information.
            Defaults to False.

    Returns:
        dict<str:np.ndarray>: 1D array containing criticality values per PandaPower element type
        float: Lowest criticality value encountered 
        float: Highest criticality value encountered
    """
    criticality = {}
    lowest, highest = math.inf, -math.inf
    def get_apparent_power(grid, attr):
        df = getattr(grid, attr)
        Sn_mva = np.zeros(shape=df.shape[0])
        if "sn_mva" in df.columns:
            Sn_mva = df.sn_mva
        # >> Lines <<
        elif attr == "line":
            # PandaPower only runs lines between the same nominal voltage
            # Maximum |Apparent Power| occurs when cos(phi) = 1 or sin(phi) = 1, i..e when S = UI
            # Assume maximum deviation in Voltage (0.1 p.u. = 10%)
            vn_kv = grid.bus.loc[df.from_bus, "vn_kv"].reset_index(drop=True)
            # Smax = UI * n_parallel * scaling_factor
            Sn_mva = vn_kv*df.max_i_ka*df.parallel*df.df # in MVA
        elif attr == "dcline":
            max_q_mvar = np.max(np.vstack([df.max_q_from_mvar, df.max_q_to_mvar]),axis=0)
            Sn_mva = np.sqrt(np.power(df.max_p_mw,2) * np.power(max_q_mvar,2))
        elif attr == "bus":
            for other_attr in pandapower.pp_elements():
                other_df = getattr(grid, other_attr).copy()
                if hasattr(other_df, "bus"):
                    # Inherit apparent power of connected elements (not lines!)
                    other_df["apparent"] = get_apparent_power(grid, other_attr)
                    # Sn_mva[other_df.bus] += other_df["apparent"]
                    for _, row in other_df.iterrows():
                        if row.bus in df.index:
                            Sn_mva[row.bus] += row.apparent
        return Sn_mva
    
    for attr in pandapower.pp_elements():
        Sn_mva = get_apparent_power(grid, attr)
        low = np.min(Sn_mva) if Sn_mva.shape[0] > 0 else lowest
        high = np.max(Sn_mva) if Sn_mva.shape[0] > 0 else highest
        lowest = low if low < lowest else lowest
        highest = high if high > highest else highest
        criticality[attr] = Sn_mva
    
    return criticality, lowest, highest