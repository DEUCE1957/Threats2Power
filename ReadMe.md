# Threats2Power

Threats2Power provides a high-level, abstract, representation of the communication network for power systems.

Features include:

* Procedural generation of communication network topologies
* Association of communication network sensors / actuators with PandaPower or Grid2Op components
* Cyber-attack simulation based on threat modelling
    * Static analysis of small communication networks
    * Monte Carlo analysis of any communication network
    * (Planned) Event-like / dynamic simulation of cyber-attacks over a period of time 
* Specifications for different communication network:
    * Supervisory Control and Data Acquisition (SCADA)
    * Protection
    * Wide Area Monitoring Systems (WAMS)
    * Smart Meters
* Grade cyber-attack based on criticality of affected components
    * Scheme 1: Cost of failure of component
    * Scheme 2: Connectivity of node in power system graph
* Visualization of the communication network topology, including which components have been compromised

## Module Layout

A rough outline of this module is shown below:

![Threats2Power.svg](Threats2Power.svg)