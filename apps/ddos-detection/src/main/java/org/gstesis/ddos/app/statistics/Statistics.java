package org.gstesis.ddos.app.statistics;


import org.gstesis.ddos.app.processor.MirrorTraffic;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.Key;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

import static java.lang.Thread.sleep;
import static org.gstesis.ddos.app.statistics.StatisticsResources.*;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * this class monitiring network trafic every 10 seconds, look for traffic suspicius
 * then get suspicius device and duplicate traffic to IDS inspection
 * @see java.lang.Runnable
 * @see org.gstesis.ddos.app.statistics.Monitoring
 */
public class Statistics implements Runnable, Monitoring {


    private final Logger log = getLogger(getClass());

    private DeviceService        deviceService;
    private LinkService          linkService;
    private IntentService        intentService;
    private NetworkConfigService netcfgService;
    private MirrorTraffic        mirrorTraffic;
    private StatisticsResources  statisticsResources;

    private ExecutorService      executor;


    /**
     * Class constructor
     * @param deviceService ONOS Service
     * @param linkService ONOS Service
     * @param topologyService ONOS Service
     * @param intentService ONOS Service
     * @param packetService ONOS Service
     * @param netcfgService ONOS Service
     * @param statisticsResources Expected values used to Map (deviceId, values) and
     *                            values [pkts, bytes]
     */
    public Statistics(DeviceService deviceService, LinkService linkService,
                      TopologyService topologyService, IntentService intentService,
                      PacketService packetService, NetworkConfigService netcfgService,
                      StatisticsResources statisticsResources) {

        this.deviceService  = deviceService;
        this.linkService    = linkService;
        this.intentService  = intentService;
        this.netcfgService  = netcfgService;
        this.statisticsResources = statisticsResources;
        this.mirrorTraffic = new MirrorTraffic( intentService, packetService, linkService,
                                                deviceService, topologyService);
        this.executor       = Executors.newFixedThreadPool(NUM_EDGES_MAX);
    }

    @Override
    public void run() {

        Set<DeviceId> distribtionDevIds;  // Distribution Dev Set
        Set<DeviceId> edgesDevIds;        // Suspicios Dev Set
        List<Key>     deviatKeys;         // Intents Keys Connectios

        log.info("DoS/DDoS Detector Running");

        while (!Thread.currentThread().isInterrupted()) {

            distribtionDevIds = detectingDDoS();   // posible uso para Unir con Firewall
            if(!distribtionDevIds.isEmpty()) {
                log.info("DoS/DDoS Detected");

                // Edeges suspicious
                edgesDevIds = getEgdesSuspicios(distribtionDevIds);
                if (!edgesDevIds.isEmpty()) {

                    deviatKeys = mirrorTraffic.duplicateTraffic(edgesDevIds);
                    if (!deviatKeys.isEmpty()) {
                        try {
                            log.info("Traffic duplicated and Send to Analizer");

                            executor.execute(new Analizer(this.netcfgService, this.intentService,
                                                          edgesDevIds, deviatKeys));

                        } catch (RejectedExecutionException e) {
                            log.error("Executor num MAX execeded (MAX={}) ", NUM_EDGES_MAX);
                        }
                    }
                }
            }
            try {
                sleep(10000); // intervalo de tiempo 10s
            } catch (Exception e) {
                executor.shutdownNow();
                log.error("Thread Interrupido abrutamente");
                return;
            }
        }
    }

    /**
     * Implementa el Algoritmo3 de Fang Leu
     *
     * @return true si H0 se rechaza, false si H0 es cierta
     */
    private Set<DeviceId> detectingDDoS() {

        int                 nDstr;     // distribution dev count
        long                nCount;
        long                nBytes;
        long[]              arrayNCant;
        long[]              arrayNSize;

        Set<DeviceId>       suspuciosDev;        // Set Suspicios Dev

        DeviceId[]          arrayDistribtionIds; // Distribution devs
        Set<DeviceId>       DistributionIdSet;
        Set<PortStatistics> portStatistics;      // Statistics per dev

        suspuciosDev      = new HashSet<>();

        //Get all DevicesId of Distribution Devices
        DistributionIdSet = getDevIdsByAnnot(this.deviceService, STR_DISTRIBTION, this.log);
        if (DistributionIdSet.isEmpty()) {
            log.error("Dont find Distribution Devices");
            return suspuciosDev;
        }

        nDstr               = DistributionIdSet.size();
        arrayNCant          = new long[nDstr];
        arrayNSize          = new long[nDstr];

        arrayDistribtionIds = DistributionIdSet.toArray(new DeviceId[nDstr]);

        // Por cada Ditribtuion obtengo las estadisticas de los puertos
        // conectados a un EDGE, El index de arrayDistribtionIds es el mismo
        // para arrayNCant y arrayNSize
        for (int i = 0; i < arrayDistribtionIds.length; i++) {

            portStatistics = getStatisticsEdgePorts(this.deviceService, this.linkService,
                                                    arrayDistribtionIds[i], this.log);
            if (!portStatistics.isEmpty()) {
                nCount = 0;
                nBytes = 0;
                for (PortStatistics stat : portStatistics) {
                    try {
                        nCount += stat.packetsReceived();
                        nBytes += stat.bytesReceived();
                    } catch (NullPointerException e) {
                        log.error("Dont detected Ports Statistics");
                        return suspuciosDev;
                    }
                }
                arrayNSize[i] = nBytes;
                arrayNCant[i] = nCount;
            } else {
                arrayNSize[i] = 0;
                arrayNCant[i] = 0;
            }
        }

        // Detect Resourse Cosumption
        if(isConsumption(arrayNCant, DAY_COUNT)){
            // Check wich Edges devices issued the attack
            suspuciosDev.addAll(checkDevice(arrayDistribtionIds, arrayNCant, DAY_COUNT));
        }

        // Detect Band Width Cosumption
        if(isConsumption(arrayNSize, DAY_BYTES)){
            // Check wich Edges devices issued the attack
            suspuciosDev.addAll(checkDevice(arrayDistribtionIds, arrayNSize, DAY_BYTES));
        }
        return suspuciosDev;
    }


    /**
     * Global Chi Square analisys
     * @param observed, values observed
     * @param var indica el analisis a realizar COUNT or BYTES.
     * @return false si H0; true si H1
     */
    private boolean isConsumption( long[] observed, int var){

        double xpexted;
        double chiSquare;
        long[] conters;

        conters   = this.statisticsResources.getTotalExpexted();
        //weekCount/AVG_ACUMULATE; (PKTRX * 8) = (12322 * 8)
        xpexted   = conters[var]/AVG_ACUMULATE;
        chiSquare = 0;
        
        long cant_observada_trafico_10_s = 0; // N value (trafico observado).

        for (long obsVale : observed) {
            chiSquare += ((obsVale - xpexted) < 0.0)? 0.0 : (obsVale - xpexted) / xpexted;
            cant_observada_trafico_10_s = cant_observada_trafico_10_s + obsVale;
        }

        log.debug("Chi Square Result for {} :{}", (var==DAY_BYTES)? "BYTES":"PACKETS", chiSquare);
        
        // Using for GET web
                
        String dato_resources = Double.toString(chiSquare);
        // Agrego valor de chi cuadrado.
        ChiResources.getInstance().setChiSquareValues(dato_resources);

        dato_resources = Long.toString(cant_observada_trafico_10_s);//N value
        // Agrego valor de N (trafico observado).
        ChiResources.getInstance().setChiSquareValues(dato_resources);

        Calendar calendario = Calendar.getInstance();
        calendario.setTimeZone(TimeZone.getTimeZone("America/Argentina/Buenos_Aires"));
        
        String time = Integer.toString(calendario.get(Calendar.HOUR_OF_DAY)) + new String(":")
            + Integer.toString(calendario.get(Calendar.MINUTE)) + new String(":")
            + Integer.toString(calendario.get(Calendar.SECOND));
        
        dato_resources = time;//Timestamp. (HH:MM:SS).
        // Agrego valor de timestamp.
        ChiResources.getInstance().setChiSquareValues(dato_resources);
        
        return chiSquare > GLOBAL_CHI_VALE;
    }

    /**
     * Chi Square Analysis for every "distribution" device
     * @param distributionDevs, Array "distribution" device
     * @param observed, values observed per every "distribution" device
     * @param var, indica el analisis a realizar COUNT or BYTES.
     * @return Set<DeviceId> Suspicios "Distribution" Devices Set.
     */
    private Set<DeviceId> checkDevice(DeviceId[] distributionDevs, long[] observed, int var){

        double        expexted;
        double        chiSquare;
        Set<DeviceId> suspuciosDev;

        suspuciosDev = new HashSet<>();

        // log.info("Entre aqui con {}", (var==DAY_BYTES)? "BYTES":"PACKETS");
        // El index de distributionDevs es el mismo para observed
        for (int i = 0; i < distributionDevs.length; i++) {

            expexted  = this.statisticsResources.getExpectedForDevice(distributionDevs[i], var);
            expexted  = expexted/AVG_ACUMULATE;

            chiSquare = ((observed[i] - expexted) < 0.0)?
                         0.0 : Math.pow(observed[i] - expexted, 2)/expexted;

            // log.info("Distribution Dos/DDoS:{}, observed: {} , Expected:{} {}",
            //        distributionDevs[i], observed[i], expexted,
            //        (var==DAY_BYTES)? "BYTES":"PACKETS");*/

            if(chiSquare > UMBRAL_DEV_DISTRIBUTION) {

                log.info("Distribution Dos/DDoS:{}, ChiSquare: {}", distributionDevs[i], chiSquare);
                // agregado de todos los devices "Distribution"
                suspuciosDev.add(distributionDevs[i]);
                //suspuciosDev.addAll(getEdgesConnected(deviceService, linkService, distributionDevs[i], log));
            }
        }
        return suspuciosDev;
    }

    /**
     * Get all Edeges devices directly connected Distribtion devs Set
     * @param distribtionDevIds, Distribtion devs Set
     * @return Set<DeviceId> Edeges devices directly connected
     */
    private Set<DeviceId> getEgdesSuspicios(Set<DeviceId> distribtionDevIds) {

        double              nCountTotal ;
        double              nBytesTotal ;

        DeviceId            edgeId;
        Set<DeviceId>       edgeSuspuciosDev;
        Set<DeviceId>       tmpSuspuciosDev;
        Set<PortStatistics> portStatistics;      // Statistics per dev

        edgeSuspuciosDev = new HashSet<>();

        if (distribtionDevIds.isEmpty())
            return edgeSuspuciosDev;

        for (DeviceId distribtionId : distribtionDevIds) {
            // Get statistics per port connected to Edge
            portStatistics = getStatisticsEdgePorts(this.deviceService, this.linkService,
                                                    distribtionId, this.log);
            if (!portStatistics.isEmpty()) {

                nCountTotal = 0;
                nBytesTotal = 0;
                // Calculate total Statistics for every device
                for (PortStatistics stat : portStatistics) {
                    try {
                        nCountTotal += stat.packetsReceived();
                        nBytesTotal += stat.bytesReceived();
                    } catch (NullPointerException e) {
                        log.error("Dont detected Ports Statistics");
                    }
                }
                tmpSuspuciosDev = new HashSet<>();
                for (PortStatistics stat : portStatistics) {
                    try {
                        // Determinete the highest Metrics
                        if(stat.packetsReceived()/nCountTotal    >= 0.8 ||
                                stat.bytesReceived()/nBytesTotal >= 0.8){
                            // Chosse highest Devices
                            edgeId = getEdgeConnected(this.deviceService, this.linkService,
                                    distribtionId, stat.portNumber(), this.log);

                            tmpSuspuciosDev.add(edgeId);
                            log.info("Device Edge: {}  Added ", edgeId);
                        }
                    } catch (NullPointerException e) {
                        log.error("Dont detected Ports Statistics");
                    }
                }
                if(!tmpSuspuciosDev.isEmpty()){
                    // Add highest Devices
                    edgeSuspuciosDev.addAll(tmpSuspuciosDev);
                }
                else {
                    // Add all devices connected
                    edgeSuspuciosDev.addAll(getEdgesConnected(this.deviceService, this.linkService,
                            distribtionId, this.log));
                }
            }
        }
        return edgeSuspuciosDev;
    }



    /*
     * Obtencion del Edge del cual proviene el mayor flujo de trafico
     * @param devId DeviceId distribution, directamente conetado al edge
     * @param port, puero en el cual se encuentra el edege.
     * @return DeviceId del Sw edge.

    private DeviceId getConectedDevice(DeviceId devId, int port){

        DeviceId edgeId = null;
        //se obtienen todos los links conectado al dispostivo
        Set<Link> ingressLinks = this.linkService.getDeviceIngressLinks(devId);
        //busqueda en los enlaces, buscado conexiones con los edges
        for (Link link: ingressLinks) {
            if(link.dst().port().toLong() == port){
                edgeId = link.src().deviceId(); // se obtiene el edege
                break;
            }
        }
        return edgeId;
    }*/

}
