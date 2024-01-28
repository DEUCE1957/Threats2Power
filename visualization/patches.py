import inspect
import math
import numpy as np
import matplotlib.path as mpath
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D
from matplotlib.transforms import Affine2D
from matplotlib.collections import PatchCollection
from collections.abc import Iterable

class ElectricalPatchMaker():

    def __init__(self, symbol="trafo", **kwargs) -> None:
        methods = {method_name:method for method_name, method in inspect.getmembers(ElectricalPatchMaker, predicate=inspect.isfunction)}
        if symbol in methods:
            self.symbol = symbol
            self.patch, self.centroid = methods[self.symbol](self, **kwargs)
        else:
            raise ValueError(f"The symbol '{symbol}' is not currently supported.")
    
    def bus(self, x0=0, y0=0, size=1, **kwargs):
        circle = mpath.Path.circle(center=(x0, y0), radius=size)
        bus_patch = mpatches.PathPatch(circle, **kwargs)
        centroid = (x0, y0)
        return bus_patch, centroid

    def load(self, x0=0, y0=0, size=1, **kwargs):
        offset = np.array([x0, y0])
        A = np.array([-math.sqrt(3)/2, 0.5])*size+offset
        B = np.array([math.sqrt(3)/2, 0.5])*size+offset
        C = np.array([0.0, -1.0])*size+offset
        load_path = mpath.Path([A, B, C, A], [1,2,2,79])
        load_patch = mpatches.PathPatch(load_path, **kwargs)
        return load_patch, (x0, y0)
    
    def trafo(self, x0=0, y0=0, size=1, **kwargs):
        circle1 = mpath.Path.circle(center=(x0-size/2,y0), radius=size)
        circle2 = mpath.Path.circle(center=(x0+size/2,y0), radius=size)
        trafo_path = mpath.Path.make_compound_path(circle1, circle2)
        trafo_patch = mpatches.PathPatch(trafo_path, **kwargs)
        # Return Patch and its Centroid
        centroid = (x0,y0)
        return trafo_patch, centroid

    def ext_grid(self, x0=0, y0=0, size=1, **kwargs):
        ext_grid_patch = mpatches.Rectangle((x0-size/2, y0-size/2), width=size, height=size,
                                         hatch="xxx", **kwargs)
        # Return Patch and its Centroid
        centroid = x0, y0
        return ext_grid_patch, centroid

    def switch(self, x0=0, y0=0, size=1, open=True, **kwargs):
        kwargs["fc"] = "white" if open else kwargs.get("ec", "black")
        line_path = mpath.Path(vertices=[(x0-size/2, y0-size/2), (x0+size/2, y0-size/2),
                                         (x0+size/2, y0+size/2), (x0-size/2, y0+size/2),
                                         (x0-size/2, y0-size/2)], codes=[1, 2, 2, 2, 79])
        line_patch = mpatches.PathPatch(line_path, **kwargs)
        # Return Patch and its Centroid
        centroid = x0, y0
        return line_patch, centroid
    
    def sgen(self, x0=0, y0=0, size=1, joinstyle="bevel", **kwargs):
        t = size * 0.8
        circle = mpath.Path.circle(center=(x0,y0), radius=size)
        triangles = mpath.Path(vertices=[(x0-t,y0+t/2), (x0,y0+t/2), (x0-t/2, y0-t/2), (x0-t,y0+t/2), # Triangle (Down)
                                         (x0,y0-t/2), (x0+t,y0-t/2), (x0+t/2, y0+t/2), (x0,y0-t/2), # Triangle (Up)
                                         (x0-t,y0+t/2), (x0+t,y0+t/2), # Top Horizontal
                                         (x0-t,y0-t/2), (x0+t,y0-t/2),], # Bottom Horizontal
                                codes=[1,2,2,2,1,2,2,2,1,2,1,2])
        sgen_path = mpath.Path.make_compound_path(circle, triangles)
        sgen_patch = mpatches.PathPatch(sgen_path, joinstyle=joinstyle, **kwargs)
        # Return Patch and its Centroid
        centroid = (x0, y0)
        return sgen_patch, centroid
    
    @staticmethod
    def make_collection(symbol, x, y, size, **kwargs):
        patches = []
        centroids = []
        size_iterable = isinstance(size, Iterable)
        try:
            for idx in range(len(x)):
                x0, y0 = x[idx], y[idx]
                patch_size = size[idx] if size_iterable else size
                patch_maker = ElectricalPatchMaker(symbol=symbol, x0=x0, y0=y0, size=patch_size)
                patch, centroid = patch_maker.patch, patch_maker.centroid
                patches.append(patch)
                centroids.append(centroid)
        except:
            raise ValueError(f"'{symbol}' not currently supported by Patch Maker")
        # Note: Hatching does NOT work with Patch Collections
        return PatchCollection(patches, **kwargs), centroids
    
class ElectricalPatchHandler(object):

    def legend_artist(self, legend, orig_handle, fontsize, handlebox):
        patch = orig_handle.patch
        patch.set_transform(handlebox.get_transform())
        handlebox.add_artist(patch)
        return patch