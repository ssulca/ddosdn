# Topologia 
v 5.1.2

### SDN Topology 

SDN Topology similat to a ISP infrastructure.

*Simplified block of the system.*
<p style="text-align: center;">
<img src=images/topo.png width=80%>
</p>


Devices:
 * EDGE (8)
 * DISTRIBUTION (4)
 * CORE (2)
 * BORDER (1)

Hosts:
 * Common user (13)
 * Bot (7)
 * IDS (4)
 * Web Server (3)

## Use
1. Run SDN Controller
2. Run `topology.py`

Default values

```python
IP_CONTROLLER = '192.168.50.2'
PORT_CONTROLLER = 6653
```
### Commands 
 * `pingall` to test connectivity 
 * Use Docker for access to Hosts
 * ContainerNet commands in
   [Doc](https://github.com/mininet/mininet/wiki/Documentation)
