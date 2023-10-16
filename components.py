
# >> CyberSecurity <<
class Defence():
    
    def __init__(self, name:str) -> None:
        super().__init__()
        self.name = name

class Vulnerability():

    def __init__(self, name:str) -> None:
        super().__init__()
        self.name = name

class CyberComponent():

    def __init__(self) -> None:
        super().__init__()
        self.defences = OrderedDict()
        self.vulnerabilities = OrderedDict()

    def add_defence(self, defence:Defence):
        self.defences[defence.name] = defence

    def remove_defence(self, defence:Defence|str) -> Defence:
        name = defence.name if isinstance(defence, Defence) else defence
        return self.defences.pop(name)
    
    def add_vulnerability(self, vulnerability:Vulnerability):
        self.vulnerabilities[vulnerability.name] = vulnerability

    def remove_vulnerability(self, vulnerability:Vulnerability|str) -> Vulnerability:
        name = vulnerability.name if isinstance(vulnerability, Vulnerability) else vulnerability
        return self.vulnerabilities.pop(name)

# >> Nodes <<
class Node():

    id_iter = itertools.count()

    def __init__(self, parent:None=None) -> None:
        super().__init__()
        self.id = next(self.id_iter)
        self.parent = parent
        self.children = []
        self.outgoing_edges = []
        self.incoming_edges = []

    def set_parent(self, parent):
        self.parent = parent
        self.parent.add_child(self)

    def add_child(self, *children):
        self.children.extend(children)

    def add_outgoing_edge(self, other, edge):
        edge.source = self
        self.outgoing_edges.append(edge)
        if edge.target is None:
            other.add_incoming_edge(self, edge)

    def add_incoming_edge(self, other, edge):
        edge.target = self
        self.incoming_edges.append(edge)
        if edge.source is None:
            other.add_outgoing_edge(self, edge)

    def reset_edges(self):
        self.edges = []

    def reset_children(self):
        self.children = []
    
    def __str__(self):
        return f"{self.__name__}(id={self.id})"

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return self.id == other.id

class Aggregator(CyberComponent, Node):

    __name__ = "Aggregator"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
    
    def aggregate(self):
        pass

class Device(CyberComponent, Node):

    __name__ = "Device"

    def __init__(self, is_controller:bool, is_sensor:bool, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.is_controller = is_controller
        self.is_sensor = is_sensor
    
    def collect(self):
        pass

    def act(self):
        pass

# >> Edges <<
class Link():

    def __init__(self, source=None, target=None) -> None:
        super().__init__()
        self.source = source
        self.target = target
        self.attributes = {}

    def to_edge(self):
        return dict(u_of_edge=self.source, v_of_edge=self.target, attr=self)

class WiredLink(Link):

    def __init__(self, *args) -> None:
        super().__init__(*args)

class WirelessLink(Link):

    def __init__(self, *args) -> None:
        super().__init__(*args)