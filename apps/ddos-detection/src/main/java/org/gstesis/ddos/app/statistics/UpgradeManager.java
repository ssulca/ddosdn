package org.gstesis.ddos.app.statistics;

import org.gstesis.ddos.app.AppError;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.link.LinkService;
import org.slf4j.Logger;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.gstesis.ddos.app.statistics.StatisticsResources.*;
import static org.gstesis.ddos.app.statistics.StatisticsResources.DAY_BYTES;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * This class update Metrics per day in 7 days window
 * @see java.lang.Runnable
 * @see Monitoring
 */
public class UpgradeManager implements Runnable, Monitoring {

    // day 24, week 7
    private static final int MAX_SLEEP = 60; //57007; // modif para una hora

    private final Logger  log  = getLogger(getClass());

    //////////////////////////// ONOS Services /////////////////////////////
    private StatisticsResources statisticsResources;
    private DeviceService       deviceService;
    private LinkService         linkService;

    /**
     * Public Constructor
     * @param deviceService Onos Device Service
     * @param linkService   Onos Link Service
     * @param statisticsResources Class contains Statistics Resources like
     *                            Expected values for every Distribution device
     *                            and Total expected values.
     *
     * @see org.onosproject.net.device.DeviceService
     * @see org.onosproject.net.link.LinkService
     * @see StatisticsResources
     */
    public UpgradeManager(DeviceService deviceService, LinkService linkService,
                          StatisticsResources statisticsResources){
        this.statisticsResources = statisticsResources;
        this.deviceService       = deviceService;
        this.linkService         = linkService;
    }

    /**
     * Update metrics, it take init value and final values then calculate diference
     * and check values. If these are corrects update
     */
    @Override
    public void run() {
        HashMap<String, long[]> statisticsDevMapDay;
        AppError                code;

        // Get new tables entries and update table
        while(!Thread.currentThread().isInterrupted()) {
            // get Values at initDay
            statisticsDevMapDay = getNewEntry();
            try {
                //sleep(MAX_SLEEP);
                TimeUnit.MINUTES.sleep(MAX_SLEEP);
            } catch (Exception e) {
                log.error("despertado mal");
                return;
            }
            // update values initDay - endDay
            statisticsDevMapDay = getDiferenceMap(statisticsDevMapDay, getNewEntry());
            if(statisticsDevMapDay != null){
                // update table
                code = statisticsResources.putEntryTable(statisticsDevMapDay);
                log.info("update table {}", code);
            }
            else{
                log.error("Dont Update Code error: {}", AppError.NULL);
            }
        }
    }


    /**
     * Get Statistics Total.
     * @return Map vales
     */
    private HashMap<String, long[]> getNewEntry(){

        long[]                  values;
        Set<DeviceId>           DistributionIdSet;
        Set<PortStatistics>     portStatistics;
        HashMap<String, long[]> statisticsDevMap;

        // obtengo los Distr devices
        DistributionIdSet = getDevIdsByAnnot(this.deviceService, STR_DISTRIBTION, this.log);
        if(DistributionIdSet.isEmpty()) {
            log.error("No se encontraron Distribution for update");
            return null;
        }

        statisticsDevMap = new HashMap<>();

        // Por cada Ditribtuion obtengo las estadisticas de los puertos conectados a un EDGE
        for (DeviceId devId: DistributionIdSet) {
            portStatistics = getStatisticsEdgePortsTotal(this.deviceService,
                    this.linkService, devId, this.log);
            if(!portStatistics.isEmpty()) {
                values = new long[2];
                // values[DAY_COUNT] = 0;
                // values[DAY_BYTES] = 0;
                for (PortStatistics stat : portStatistics) {
                    try {
                        values[DAY_COUNT] += stat.packetsReceived();
                        values[DAY_BYTES] += stat.bytesReceived();
                    } catch (NullPointerException e) {
                        log.error("Dont detected Ports Statistics");
                    }
                    // Agrega las entradas correspondientes en el map
                    statisticsDevMap.put(devId.toString(), values);
                }
            }
        }
        return statisticsDevMap;
    }

    /**
     * Calcula la difencia entre los componentes de un Map
     * siempre que sean iguales
     * @param initVal, Map
     * @param endVal, Map
     * @return HashMap (endVal - initval)
     */
    private HashMap<String, long[]> getDiferenceMap(HashMap<String, long[]> initVal,
                                                   HashMap<String, long[]> endVal) {

        long[] newValue;
        long[] tmp;
        HashMap<String, long[]> dayMap0;
        // ConcurrentHashMap<String, long[]> devExpectedMap;

        if (initVal == null || endVal == null) {
            return null;
        }
        if (initVal.isEmpty() || endVal.isEmpty()) {
            return null;
        }
        if (initVal.size() != endVal.size()){
            return null;
        }

        dayMap0 = new HashMap<>();
        // devExpectedMap = initVal.keySet();
        // Do Diference
        for (Map.Entry<String, long[]> entry : initVal.entrySet()) {
            newValue            = endVal.get(entry.getKey());
            tmp                 = initVal.get(entry.getKey());
            newValue[DAY_COUNT] = newValue[DAY_COUNT]-tmp[DAY_COUNT];
            newValue[DAY_BYTES] = newValue[DAY_BYTES]-tmp[DAY_BYTES];
            dayMap0.put(entry.getKey(), newValue);
        }

        return dayMap0;
    }

}
