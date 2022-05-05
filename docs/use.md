# ddosdn use
## Run topology

run topology and install apps. Info in install [guide](install.md)
```
python3 topo.py
```
### Normal traffic
 using `siege` whit flag `-i` in `usr` containers (autoconfigured)

### Irregular traffic
 use `hping3` from `bot` containers

### IDS
connect `snort` containers to ONOS controller using
[`pigrelay.py`](../envr/snort/dev/pigrelay.py)

in `snort` containers

```bash
python2 pigrelay.py
```

use `snort` to inspect traffic when it is upper than a boundary

### Behavior

ddos-deteccion

*Duplicate suspicious traffic.*
<p style="text-align: center;">
<img src=images/cap4.png width=60%>
</p>


ddos-mitigation

*Filtrate suspicious traffic.*
<p style="text-align: center;">
<img src=images/cap5.png width=60%>
</p>


To see alarms use Fault Managment REST ([info](https://wiki.onosproject.org/display/ONOS/Fault+Management))

There is an example of how to read from rest API on
[statistics](../notebooks/statistics.ipynb) notebook.
