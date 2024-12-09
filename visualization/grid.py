import math
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.transforms import Affine2D
from pathlib import Path
from matplotlib.cm import ScalarMappable
from matplotlib.colors import Normalize, LogNorm
from communication.network import CommNetwork
from visualization.patches import ElectricalPatchMaker, ElectricalPatchHandler


def update_connected_equipment(network:CommNetwork, kind:str="bus"):
    """
    Given a communication network, finds which physical equipment communication
    network devices (leaf nodes) map to on the physical grid (if any) and 
    whether these have been compromised as a result.
    """
    grid = network.grid
    equip_df = getattr(grid, kind)
    if kind in network.equip_to_device:
        eqp_idx_to_device = network.equip_to_device[kind]
        is_compromised = {}
        for eqp_idx, device_ids in eqp_idx_to_device.items():
            for device_id in device_ids:
                device = network.id_to_node[device_id]
                if device.is_compromised:
                    # If any connected device is compromised, mark equipment as compromised
                    is_compromised[eqp_idx] = True
                    break
        equip_df["Connected"] = equip_df.index.isin(eqp_idx_to_device)
        equip_df["Compromised"] = equip_df.index.isin(is_compromised)
    else:
        equip_df["Connected"] = False
        equip_df["Compromised"] = False
    return equip_df

def rotate_to_align(start, end):
    """
    Given 2 points on a straight line, find the rotation angle (in radians) needed to
    align a symbol (pointing up) to the line
    """
    x1, y1 = start
    x2, y2 = end
    angle = math.atan((y2 - y1)/(x2 - x1))
    return angle

def place_along_line(start, end, pos=0.5):
    """
    Given 2 points on a straight line, return a position
    some fraction (0 to 1) along it.
    """
    if pos < 0 or pos > 1.0:
        raise ValueError(f"Position {pos} is not between 0.0 and 1.0")
    x1, y1 = start
    x2, y2 = end
    return x1+(x2 - x1)*pos, y1+(y2-y1)*pos

def add_symbol(ax, grid, symbol, distance, rotation, displace=True, **kwargs):
    df = getattr(grid, symbol)
    # How many instances of this symbol this bus has (e.g. 2x load)
    counts = df.bus.value_counts()
    current_count = {}
    coords = []
    for i, bus_idx in enumerate(df.bus):
        patch_kwargs = {k:v[i] if isinstance(v, list) else v for k,v in kwargs.items()}
        x, y = grid.bus_geodata.loc[bus_idx, ["x", "y"]]
        current_count[bus_idx] = current_count[bus_idx] + 1 if bus_idx in current_count else 0
        count = current_count[bus_idx]
        total_count = counts[bus_idx]
        if not displace:
            patch_kwargs["alpha"] = 1.0 if count == 0 else 1/total_count
        patch_maker = ElectricalPatchMaker(symbol=symbol, x0=x, y0=y, **patch_kwargs)

        # Translate symbol some distance from its bus
        translation = Affine2D().translate(distance, 0)
        translated_pos = (patch_maker.centroid[0] + distance, patch_maker.centroid[1])

        # Rotate symbol about its center (ensures it is upright at the end)
        extra_rotation = count*np.pi/16 if displace else 0
        off_rotate = Affine2D().rotate_around(*translated_pos, -rotation-extra_rotation)

        # Rotate around bus
        rel_rotate = Affine2D().rotate_around(*patch_maker.centroid, rotation+extra_rotation)

        # Apply transformation to symbol (and update centroid)
        transform = translation + off_rotate + rel_rotate + ax.transData
        patch_maker.patch.set_transform(transform)
        patch_maker.centroid = rel_rotate.transform_point(translated_pos)
        patch, (x0, y0) = patch_maker.patch, patch_maker.centroid
        coords.append((x0, y0))

        # Draw line from bus to symbol (behind everything else)
        ax.plot([x, x0], [y, y0], color="black", lw=1, zorder=-10)
        # Add patch to Axis (to draw it)
        ax.add_patch(patch)
        if not displace and total_count > 1:
            ax.annotate(text:=f"x{total_count}", xytext=(x0+(distance/2)*(len(text)-1), y0), xy=(x0,y0), zorder=-10)
        
    legend_entry = ElectricalPatchMaker(symbol=symbol, x0=15, y0=5, size=10, lw=2,
                                        fc="white", ec="black")
    return ax, legend_entry, coords

def add_buses(ax, grid, s=200, **kwargs):
    bus = ElectricalPatchMaker("bus")
    coords = [(x,y) for x,y in zip(grid.bus_geodata.x, grid.bus_geodata.y)]
    ax.scatter(x=grid.bus_geodata.x, y=grid.bus_geodata.y,
               marker=bus.patch.get_path(), s=s,
               label=grid.bus_geodata.index, **kwargs)
    if s >= 200: # Marker must be big enough to show text
        for bus_idx in grid.bus_geodata.index:
            x, y = grid.bus_geodata.loc[bus_idx].x, grid.bus_geodata.loc[bus_idx].y
            ax.annotate(bus_idx, xy=(x,y), zorder=20, color="white", ha="center", va="center")
    legend_entry = ElectricalPatchMaker(symbol="bus", x0=15, y0=5, size=10, lw=2,
                                        fc="white", ec="black")
    return ax, legend_entry, coords

def add_transformers(ax, grid, **kwargs):
    startx, starty = grid.bus_geodata.loc[grid.trafo.hv_bus].x, grid.bus_geodata.loc[grid.trafo.hv_bus].y
    endx, endy = grid.bus_geodata.loc[grid.trafo.lv_bus].x, grid.bus_geodata.loc[grid.trafo.lv_bus].y
    coords = []
    for i, (x0, y0, x1, y1) in enumerate(zip(startx, starty, endx, endy)):
        patch_kwargs = {k:v[i] if isinstance(v, list) else v for k,v in kwargs.items()}
        # Plot line between buses that transformer connects
        plt.plot([x0, x1], [y0, y1], color="black", zorder=-1)

        # Create Transformer Symbol (2 nested circles)
        coords.append((x0 := (x1+x0)/2, y0 := (y1+y0)/2))
        trafo = ElectricalPatchMaker(symbol="trafo", x0=x0, y0=y0, **patch_kwargs)

        # Rotate the Transformer symbol to align with the line it is on
        rotate = Affine2D().rotate_around(*trafo.centroid, rotate_to_align((x0,y0), (x1,y1)))
        transform = rotate + ax.transData
        trafo.patch.set_transform(transform)

        ax.add_patch(trafo.patch)
    legend_entry = ElectricalPatchMaker(symbol="trafo", x0=12, y0=4, size=5, lw=2,
                                        fc="white", ec="black")
    return ax, legend_entry, coords

def add_switches(ax, grid, **kwargs):
    switches = grid.switch#[grid.switch.et == "l"]
    coords = []
    for idx in switches.index:
        # Switch Element (placed towards a bus, on a specific line)
        switch = switches.loc[idx]

        # Find line that this switch is placed at
        if switch.et == "l":
            line_with_switch = grid.line.loc[switch.element]
            from_bus, to_bus = line_with_switch.from_bus, line_with_switch.to_bus
        elif switch.et == "t":
            trafo_with_switch = grid.trafo.loc[switch.element]
            from_bus, to_bus = trafo_with_switch.lv_bus, trafo_with_switch.hv_bus
        
        # Find the start and end points of the switch's line
        end_point_buses = grid.bus_geodata.loc[[from_bus,to_bus]]
        x0, x1 = end_point_buses.x.values
        y0, y1 = end_point_buses.y.values
        xpos, ypos = place_along_line((x0,y0),(x1, y1), pos=0.8 if to_bus == switch.bus else 0.2)
        coords.append((xpos, ypos))

        # Create Line Switch Element (Patch)
        switch = ElectricalPatchMaker(symbol="switch", x0=xpos, y0=ypos,
                                           open=not switch.closed, **kwargs)
        
        # Transform to align with the line
        rotate = Affine2D().rotate_around(*switch.centroid, rotate_to_align((x0,y0), (x1,y1)))
        transform = rotate + ax.transData
        switch.patch.set_transform(transform)
        switch.centroid = rotate.transform_point(switch.centroid)

        # Display the Line Switch
        ax.add_patch(switch.patch)
    legend_entry = ElectricalPatchMaker(symbol="switch", x0=12, y0=5, size=10, lw=2,
                                        fc="white", ec="black")
    return ax, legend_entry, coords

def color_by_comm(network, kind, connected_color="purple", compromised_color="red", cmap="plasma"):
    df = update_connected_equipment(network, kind=kind)
    df["Color"] = "black"
    df.loc[df.Connected, "Color"] = connected_color
    df.loc[df.Compromised, "Color"] = compromised_color
    return list(df.Color)

def color_by_criticality(network, kind, cmap="plasma"):
    criticality = network.criticality[kind]
    highest = max([np.max(array) for array in network.criticality.values() if len(array) > 0])
    norm = Normalize(vmin=0, vmax=1)
    sm = mpl.cm.ScalarMappable(norm=norm, cmap=mpl.colormaps[cmap])
    colors = sm.to_rgba(criticality / highest)
    return list(colors)

def plot_physical_grid(network:CommNetwork,
                       ax=None, show:bool=True, show_legend:bool=True, show_colorbar:bool=False,
                       color_by="color_by_comm", palette="plasma",
                       size=0.2, distance=0.5, displace=True, save_name:str=None,
                       ext_grid_rotation=np.pi/2, gen_rotation=np.pi/2, load_rotation=-np.pi/2, figsize=None):
    grid = network.grid
    color_by = {"color_by_comm":color_by_comm, "color_by_criticality":color_by_criticality}.get(color_by, "color_by_comm")

    if ax is None:
        _, ax = plt.subplots(nrows=1, ncols=1, figsize=figsize)
    ax.axis("off")
    coords = {}

    # Buses
    ax, bus, coords["bus"] = add_buses(ax, grid, c=color_by(network, "bus", cmap=palette),
                        ec=color_by(network, "bus", cmap=palette), s=size*1000, zorder=11)
    # Lines
    startx, starty = grid.bus_geodata.loc[grid.line.from_bus].x, grid.bus_geodata.loc[grid.line.from_bus].y
    endx, endy = grid.bus_geodata.loc[grid.line.to_bus].x, grid.bus_geodata.loc[grid.line.to_bus].y
    line_colors = color_by(network, "line", cmap=palette)
    for i, (x0, y0, x1, y1) in enumerate(zip(startx, starty, endx, endy)):
        plt.plot([x0, x1], [y0, y1], color=line_colors[i], zorder=-1)
        coords["line"] = coords["line"] + [((x0+x1)/2, (y0+y1)/2)] if "line" in coords else [((x0+x1)/2, (y0+y1)/2)]

    # Transformers (placed on line)
    ax, trafo, coords["trafo"] = add_transformers(ax, grid, size=size*0.8,
                                 ec=color_by(network, "trafo", cmap=palette), fc="white", zorder=10)

    # Line Switches (placed on line)
    ax, switch, coords["switch"] = add_switches(ax, grid, size=size, ec="black", zorder=10)
    
    # Static Generators
    ax, sgen, coords["sgen"] = add_symbol(ax, grid, symbol="sgen", distance=distance,
                          rotation=gen_rotation, displace=displace,
                          size=size, fc="white", ec=color_by(network, "sgen", cmap=palette), zorder=10)

    # Loads
    ax, load, coords["load"] = add_symbol(ax, grid, symbol="load", distance=distance, 
                          rotation=load_rotation, displace=displace,
                          size=size, fc="white", ec=color_by(network, "load", cmap=palette), zorder=10)
    
    # External Grid
    ax, ext_grid, coords[ext_grid] = add_symbol(ax, grid, symbol="ext_grid", distance=distance,
                              rotation=ext_grid_rotation, displace=displace, lw=1,
                              size=size*2, ec=color_by(network, "ext_grid", cmap=palette), fc="white", zorder=10)
    ax.set(aspect="equal", xticks=[], yticks=[])
    
    # Legend (with custom symbols)
    legend_map = {"Bus":bus, "Generator":sgen, "Load":load, "Transformer":trafo,
                  "External Grid":ext_grid, "Switch":switch}
    labels, handles = zip(*sorted(zip(*(legend_map.keys(), legend_map.values())), key=lambda t: t[0]))
    nrows = 1 + (len(labels) // 3)
    if show_legend:
        ax.legend(labels=labels, handles=handles, loc="lower center",
                bbox_to_anchor=(0.5, -0.04*nrows), ncol=min(len(labels), 3),
                handler_map={patch_maker:ElectricalPatchHandler() for patch_maker in handles},
                title="Legend", fancybox=True, fontsize='large', title_fontsize='larger')
    if show_colorbar and color_by == color_by_criticality:
        lowest = min([np.min(array) for array in network.criticality.values() if len(array) > 0 and np.min(array) > 0])
        highest = max([np.max(array) for array in network.criticality.values() if len(array) > 0])
        norm = LogNorm(vmin=lowest, vmax=highest)
        plt.gcf().colorbar(ScalarMappable(norm=norm, cmap=mpl.colormaps[palette]), ax=ax, label="Criticality")
    if save_name is not None:
        plt.gcf().savefig(Path(__file__).parent.parent / "media" / f"{save_name}.pdf", bbox_inches='tight')
    if show:
        plt.show()
    return handles, labels, coords