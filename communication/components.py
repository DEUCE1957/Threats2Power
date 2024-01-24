from pandapower.toolbox import pp_elements
from communication.graph import CommNode
from cyber.assets import CyberDevice


class Equipment():
    __name__ = "Equipment"

    def __init__(self, name:str, kind:pp_elements(), *args, **kwargs) -> None:
        """
        Representation of specific PandaPower equipment, such as a transformer ('trafo') or
        a generator ('gen').
        """
        
        self.name = name
        self.kind = kind
        self.criticality = 0
        self.id = f"{self.kind}_{self.name}"

    def __str__(self):
        return self.id
    
    def __hash__(self):
        return hash(str(self))

class Aggregator(CyberDevice, CommNode):
    __name__ = "Aggregator"

    def __init__(self, *args, **kwargs) -> None:
        """
        Generic communication network component that aggregates data from 1 or more sources.
        The Aggregator can be hacked, which can also impact the reliability of all downstream data. 
        """
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"{self.name}(id={self.id}, is_accessible={self.is_accessible})"

class Device(CyberDevice, CommNode):
    __name__ = "Device"

    def __init__(self, is_controller:bool, is_sensor:bool, is_autonomous:bool=False, equipment:Equipment=None, *args, **kwargs) -> None:
        """
        Generic communication network component that collects data and/or acts in the real world.
        The device can be hacked, which impacts the trustworthiness of the data the device emits.

        Args:
            is_controller (bool): Whether the device controls a real-world object,
                such as the power output of battery
            is_sensor (bool): Whether the device collects data about a real-world object,
                such as the state of charge of a battery
            is_autonomous (bool): Whether the device can independently make decisions
                such as when to charge the battery. Always false is device is not a controller.
            equipment (Equipment): PandaPower equipment that the Device is associated with
        """
        super().__init__(*args, **kwargs)
        self.is_controller = is_controller
        self.is_autonomous = False if not self.is_controller else is_autonomous
        self.is_sensor = is_sensor
        self.equipment = equipment

    def __str__(self):
        return (f"{self.name}(id={self.id}, is_controller={self.is_controller}, " +
                f"is_autonomous={self.is_autonomous}, is_sensor={self.is_sensor}, is_accessible={self.is_accessible})")