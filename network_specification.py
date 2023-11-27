import json
import inspect
from scipy.stats import distributions as distr

class SpecEncoder(json.JSONEncoder):

    def default(self, obj):
        # Scipy Distributions
        if hasattr(obj, "dist"):
            return {"distribution": {"name":obj.dist.name, "kwds": obj.kwds}}
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)
    
def is_distribution_generator(member):
    if inspect.isclass(member):
        return member.__name__.endswith("_gen")
    return False

class SpecDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)
        valid_names = set(name[:-4] for name, _ in inspect.getmembers(distr, predicate=is_distribution_generator))
        self.distr_lookup = {name:member for name, member in inspect.getmembers(distr) if name in valid_names}

    def object_hook(self, dct):
        # Scipy Distributions
        if 'distribution' in dct:
            dist_dict = dct["distribution"]
            if dist_dict['name'] in self.distr_lookup:
                return self.distr_lookup[dist_dict['name']](**dist_dict["kwds"])
        return dct
