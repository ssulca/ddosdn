package org.gstesis.ddos.app.statistics;

// import org.slf4j.Logger;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.gstesis.ddos.app.statistics.StatisticsResources.*;
// import static org.slf4j.LoggerFactory.getLogger;

/**
 * This class contiains statistics for 7 day for every DISTRIBUTION
 * device, it is used to get expected values for statistics calc
 * @see org.gstesis.ddos.api.StatisticsWebResources
 */
public class LocalTables {

    // day 24, week 7
    // private final Logger log           = getLogger(getClass());
    private static final int TABLE_MAX = 7;

    private Queue<HashMap<String, long[]>> table;

    /**
     * Constructor using default Map (devices, values)
     * @param devExpectedMap initial Map (DeviceId, values)
     */
    public LocalTables(ConcurrentHashMap<String, long[]> devExpectedMap){
        this.table = reInitTable(devExpectedMap);
    }

    /**
     * get curret table
     * @return Queue (day , Map (DeviceId, values))
     */
    public Queue<HashMap<String, long[]>> getTable() {
        return this.table;
    }

    /**
     * Update tables for every day or (entry time)
     * @param dayMap0 Map (DeviceId, values)
     * @return if update is correct true, nor false
     */
    public synchronized boolean updateTables(HashMap<String, long[]> dayMap0){


        // Update Tabla
        this.table.remove();
        this.table.add(dayMap0); // actualizado la tabla

        // Aqui esta la magia... solo si funcionaria =(
        //this.devExpectedMap = expectedCalc;
        // Update total Values
        //updateTotalExpected();
        return true;
    }
    /*
    public synchronized ConcurrentHashMap<String,long[]> getExpextedTotalForDevice(){
        long []                 tmp;
        long []                 nuevo;
        Set<String>             keySet;
        ConcurrentHashMap<String,long[]> expectedCalc;
        keySet = oldTotalExpected.keySet();
        //StatisticsResources.getInstance().getDevExpectedMap().keySet();
        // Init new Expected Map
        expectedCalc = new ConcurrentHashMap<>();
        for (String device: keySet) {
            expectedCalc.put(device, new long[2]);
        }

        // Adder Reduction for every entry Map i every entry table
        for (Map<String, long[]> map: this.table) {
            for (String device: keySet){
                nuevo = expectedCalc.get(device);
                tmp   = map.get(device);

                nuevo[DAY_COUNT] += tmp[DAY_COUNT];
                nuevo[DAY_BYTES] += tmp[DAY_BYTES];

                expectedCalc.replace(device, nuevo);
            }
        }
        return  expectedCalc;
    }*/

    /**
     * Replace new expected values
     * @param newChMap Map (deviceId, values)
     */
    public void replaceTable(ConcurrentHashMap<String,long[]> newChMap){

        Queue<HashMap<String, long[]>> newTable;

        newTable = reInitTable(newChMap);
        if(newTable != null) {
            this.table = newTable;
            //updateTotalExpected();
        }
    }

    /**
     * When update vales from external, reinitial table
     * @param newChMap, concurrent object from external update
     * @return null o new table
     */
    private Queue<HashMap<String, long[]>> reInitTable(ConcurrentHashMap<String,long[]> newChMap){

        long []                 aux;
        Set<String> strDeviceSet;
        HashMap<String, long[]> fisrtEntryTable ;
        Queue<HashMap<String, long[]>> table;


        if (newChMap.isEmpty()) {
            return null;
        }

        strDeviceSet = newChMap.keySet();
        table = new LinkedList<>();
        fisrtEntryTable = new HashMap<>();

        for (String distribDev : strDeviceSet) {
            aux = new long[2];
            aux[DAY_COUNT] = newChMap.get(distribDev)[DAY_COUNT] / TABLE_MAX;
            aux[DAY_BYTES] = newChMap.get(distribDev)[DAY_BYTES] / TABLE_MAX;

            fisrtEntryTable.put(distribDev, aux);
            // System.out.println("tables entries "+aux[DAY_COUNT]+"::"+aux[DAY_BYTES]);
        }
        //inzializado con valores contantes
        table.add(fisrtEntryTable);

        for (int i = 0; i< TABLE_MAX-1; i++){
            table.add(new HashMap<>(fisrtEntryTable));
        }
        return table;
    }
/*

    private Queue<HashMap<String, long[]>> initTable(Queue<HashMap<String, long[]>> table) {

        long []                 aux;
        HashMap<String, long[]> entryTable;

        // definiciones segun jsonAnnotatios.json file
        String[] distribDevs = {"of:0000000000000004", "of:0000000000000005",
                "of:0000000000000006", "of:0000000000000007"};

        for (int i = 0; i< TABLE_MAX; i++){
            entryTable = new HashMap<>();

            for (String distribDev : distribDevs) {

                aux = new long[2];
                aux[DAY_COUNT] = INITIAL_COUNT / NUM_DEV_DSTR;
                aux[DAY_BYTES] = INITIAL_BYTES / NUM_DEV_DSTR;

                entryTable.put(distribDev, aux);
            }
            //inzializado con valores contantes
            table.add(entryTable);
        }

        log.info("Init Table For {} days Byes={}, pks={}", TABLE_MAX,
                INITIAL_COUNT/NUM_DEV_DSTR,
                INITIAL_BYTES/NUM_DEV_DSTR);
        return table;
    }

 */
}
