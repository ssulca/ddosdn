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

### behavior 

it is similar to images, which are showed in [apps](../apps/README.md)

To see alarms use Fault Managment REST
([info](https://wiki.onosproject.org/display/ONOS/Fault+Management))
