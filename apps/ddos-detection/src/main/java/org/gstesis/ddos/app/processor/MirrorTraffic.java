package org.gstesis.ddos.app.processor;

import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.Key;
import org.onosproject.net.intent.SinglePointToMultiPointIntent;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketProcessorEntry;
import org.onosproject.net.packet.PacketService;

import java.util.*;

import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * this class do forwarding packets and duplicate traffic when statiscts analisys
 * detect suspicius traffic.
 */
public class MirrorTraffic {

    private final Logger log = getLogger(getClass());

    private IntentService intentService;
    private PacketService packetService;
    private DeviceService deviceService;
    private LinkService   linkService;

    private TopologyService topologyService;

    /**
     * Constructor
     * @param intentService ONOS service
     * @param packetService ONOS service
     * @param linkService ONOS service
     * @param deviceService ONOS service
     * @param topologyService ONOS service
     *
     * @see org.onosproject.net.device.DeviceService
     * @see org.onosproject.net.intent.IntentService
     * @see org.onosproject.net.link.LinkService
     * @see org.onosproject.net.packet.PacketService
     * @see org.onosproject.net.topology.TopologyService
     */
    public MirrorTraffic(IntentService intentService, PacketService packetService,
                         LinkService linkService, DeviceService deviceService,
                         TopologyService topologyService){
        this.intentService   = intentService;
        this.packetService   = packetService;
        this.linkService     = linkService;
        this.deviceService   = deviceService;
        this.topologyService = topologyService;
    }

    /**
     * Metodo que retorna conjunto con todos lo puertos de los hosts conectados
     * switch EDGE objetivo.
     * @param edgeId deviceID del swtch
     * @return conjunto con todos los connectpoint
     */
    public Set<PortNumber> getportsConnToHost(DeviceId edgeId){

        List<Port> portList; // lista auxiliar
        Set<Link>  ingressLinks;

        Set<PortNumber> portsConnToHots = new HashSet<>();
        // puertos conectados a otros dispitivos EDGE, DISTR, etc
        Set<PortNumber> portsConnToDevs = new HashSet<>();

        //se obtienen todos los links conectado al dispostivo
        ingressLinks = this.linkService.getDeviceIngressLinks(edgeId);

        // puertos conectados a otros sw
        for (Link link : ingressLinks) {
            portsConnToDevs.add(link.dst().port());
        }

        if(portsConnToDevs.isEmpty()){
            log.error("se rompio todo no hay otros devs");
            return portsConnToHots;
        }

        portList = this.deviceService.getPorts(edgeId); // otencion de todos los puertos
        for (Port port : portList) {
            portsConnToHots.add(port.number());
        }

        // solo me quedo con aquellos que conectados a los hosts.
        // operacion diferencia de Conjunto A/B.
        portsConnToHots.removeAll(portsConnToDevs);
        return portsConnToHots;
    }



    /**
     * TOD: descripcion
     * @param deviceIdSet router EDGE objetivo Set de analisis
     * @return List<Key> Intents Keys for Host Connections
     */
    public List<Key> duplicateTraffic(Set<DeviceId> deviceIdSet){

        Key                           intentConnectedKey;
        Set<PortNumber>               portsConnHostSet;
        Set<FilteredConnectPoint>     egressCPSet;
        ReactivePacketProcessor       reactivePacketProcessor;
        List<PacketProcessorEntry>    processorEntryList;
        List<Key>                     keyIdsList;
        Host                          nearestIDSHost;

        Set<SinglePointToMultiPointIntent> sPointToMPointIntents;


        reactivePacketProcessor = null;
        keyIdsList              = new ArrayList<>();
        processorEntryList      = this.packetService.getProcessors();

        // Look for my ReactivePacketProcessor object
        for (PacketProcessorEntry procEntry : processorEntryList){
            if(procEntry.processor().getClass().equals(ReactivePacketProcessor.class)){
                reactivePacketProcessor = (ReactivePacketProcessor)procEntry.processor();
                break;
            }
        }
        if(reactivePacketProcessor == null){
            log.error("ReactivePacketProcessor Dont found");
            return keyIdsList;
        }

        // obtencion de todos los Hots ports del EDGE
        for (DeviceId deviceId : deviceIdSet) {

            // Ports connected to Hosts in DeviceId
            portsConnHostSet = getportsConnToHost(deviceId);
            // log.info("edge Cps {} for {}", portsConnHostSet.size(), deviceId);
            if (portsConnHostSet.isEmpty()) {
                continue;
            }
            // Intents where are connected ConnectPoints.
            sPointToMPointIntents = getsPointToMPointIntents(portsConnHostSet, deviceId);
            // log.info("edge intents {} for {}", sPointToMPointIntents.size(), deviceId);
            if (sPointToMPointIntents.isEmpty()) {
                continue;
            }

            // Find the nearest Ids to EdgeDevice.
            nearestIDSHost = findNearestIds(deviceId, reactivePacketProcessor);

            log.info("nearest ids {} for {}", nearestIDSHost.ipAddresses(), deviceId);

            for (SinglePointToMultiPointIntent spMpIntent : sPointToMPointIntents){

                // For every ConnectPoint connected to Edge (deviceId) deplicated
                // traffic to nearestIds (nearestIDSHost)
                egressCPSet = spMpIntent.filteredEgressPoints();
                for (FilteredConnectPoint filteredEgressCP: egressCPSet){
                    intentConnectedKey = reactivePacketProcessor
                            .setUpConnectivity(spMpIntent.filteredIngressPoint(), filteredEgressCP,
                                                nearestIDSHost, true );
                    keyIdsList.add(intentConnectedKey);
                }
            }
        }
        return keyIdsList;
    }

    /**
     * getsPointToMPointIntents, obtiene los intents de los puertos PorSet
     * para un device
     * @param portNumberSet, conjunto de puetos a buscar intents no null
     * @param deviceId, deviceId para buscar intetens
     * @return Set<SinglePointToMultiPointIntent>, conjunto de intents para el Device id
     */
    private Set<SinglePointToMultiPointIntent> getsPointToMPointIntents(Set<PortNumber> portNumberSet,
                                                                DeviceId deviceId){
        SinglePointToMultiPointIntent      spToMpntIntent;
        Iterable<Intent>                   intentSet;
        Set<SinglePointToMultiPointIntent> sPointToMPointIntents;

        sPointToMPointIntents = new HashSet<>();
        intentSet             = this.intentService.getIntents();

        for (Intent intent : intentSet) {
            if (intent.getClass().equals(SinglePointToMultiPointIntent.class)) {
                // cast
                spToMpntIntent = (SinglePointToMultiPointIntent) intent;
                if (portNumberSet.contains(spToMpntIntent.ingressPoint().port())
                        && spToMpntIntent.ingressPoint().deviceId().equals(deviceId)) {
                    sPointToMPointIntents.add(spToMpntIntent);
                } // if(edgeConnectPointSet.contains...
            } // intent.getClass().equals...
        } // for (Intent intent : intentSet)

        return sPointToMPointIntents;
    }


    /**
     * Encontrar el NIDS mas cercano al provedor de Servicio.
     * @param srcDeviceId DeviceID del servidor al que esta conectado
     * @return Host ids mas cercano al Device srcDeviceId
     */
    private Host findNearestIds(DeviceId srcDeviceId, ReactivePacketProcessor pktProccesor){

        DeviceId deviceIdConnectedIds; // srcDeviceId;
        Topology topology;

        Path               minPath;
        Set<Path>          paths;

        Set<DeviceId>      devicesIDSSet;
        Map<DeviceId,Host> deviceIdHostMap;

        topology = this.topologyService.currentTopology();

        // Map <Device,Host> Where Ids are connected
        deviceIdHostMap = pktProccesor.getDevIds();
        // Set de los ID de los IDSs
        devicesIDSSet        = deviceIdHostMap.keySet();
        deviceIdConnectedIds = devicesIDSSet.iterator().next();
        if(srcDeviceId.equals(deviceIdConnectedIds)){
            return deviceIdHostMap.get(deviceIdConnectedIds);   // caso destino un IDS
        }

        paths   = topologyService.getPaths(topology, srcDeviceId, deviceIdConnectedIds);
        minPath = paths.iterator().next();
        for(DeviceId devId: devicesIDSSet) {

            if(srcDeviceId.equals(devId)){
                return deviceIdHostMap.get(devId);  // caso de destino n IDS
            }
            paths = topologyService.getPaths(topology, srcDeviceId, devId);

            // Busca el path mas pequeño
            for (Path path: paths) {
                if (minPath.cost() > path.cost()) {

                    minPath  = path;  // camino mas corto
                    deviceIdConnectedIds = devId; // desipostico con el camino mas corto.
                }
                else if (minPath.cost() == path.cost() && Math.random() > 0.5) {

                    // Politica Random en caso que lo Paths sean iguales.
                    minPath  = path;
                    deviceIdConnectedIds = devId;
                }
            }
        }
        return deviceIdHostMap.get(deviceIdConnectedIds); // IDS Host directly Conneted to DevId
    }
}
