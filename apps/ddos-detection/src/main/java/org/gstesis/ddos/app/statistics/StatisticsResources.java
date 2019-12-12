package org.gstesis.ddos.app.statistics;

import org.gstesis.ddos.app.AppError;
import org.onlab.osgi.DefaultServiceDirectory;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.slf4j.Logger;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * this class contains default static values and expected dynamic values updated
 * @see org.gstesis.ddos.api.StatisticsWebResources
 */
public class StatisticsResources {

    // para un alfa = 0.05
    // en promedio hay 4 distribtion dev  -> 4 grados de libertad
    private static final double THRESHOLD      = 3.857;
    public static final double GLOBAL_CHI_VALE = 9.488 ; //12.5916; //3.00; //
    // en promedio hay 3 enlaces por dstr -> 3 grados de libertad
    public static final double LOCAL_CHI_VALUE = 7.8147 ;

    public static final double UMBRAL_DEV_DISTRIBUTION = 3.5;
    // 24*60*6 constante del Paper FANG_LEU;
    public static final double AVG_ACUMULATE   = 8640;

    public static final int DAY_COUNT          = 0;
    public static final int DAY_BYTES          = 1;
    public static final int NUM_EDGES_MAX      = 12;

    public static final int NUM_DEV_DSTR       = 4;

    public static final int INITIAL_COUNT      = 2962621;
    public static final int INITIAL_BYTES      = 253869705;

    ////////////// ANNOTATIOS //////////////////
    public static final String STR_DISTRIBTION = "distribution";
    public static final String STR_ANNT        = "killa";
    public static final String STR_EDGE        = "edge";
    public static final String STR_INSPECT     = "inspect";

    ////////////// Singleton ////////////////////
    private static StatisticsResources ourInstance = new StatisticsResources();
    ////////////// Variables /////////////////
    private ConcurrentHashMap<String, long[]> devExpectedMap;
    private ConcurrentHashMap<String, long[]> defaultExpectedMap;
    private LocalTables localTables;
    private long[] totalExpexted;

    ////////////// Cuncurrent Variables /////////////////
    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock  = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();


    private final Logger log     = getLogger(getClass());

    /**
     * Constructor singleton
     */
    private StatisticsResources() {
        this.devExpectedMap     = initDefaultMap();
        this.defaultExpectedMap = initDefaultMap();
        this.localTables        = new LocalTables(this.defaultExpectedMap);
        updateTotalExpected();
    }


    /**
     * Get Statistics Values
     * @return StatisticsResources singleton stance.
     */
    public static StatisticsResources getInstance() {
        return ourInstance;
    }

    /**
     * Getter Map values
     * @return map dev, long[2] values
     */
    public ConcurrentHashMap<String, long[]> getDevExpectedMap() {
        // read values Multiple writters one reader
        readLock.lock();
        try{
            if(devExpectedMap.isEmpty())
                return this.defaultExpectedMap;
            else
                return this.devExpectedMap;
        }
        catch (Exception e){
            return null;
        }
        finally {
            readLock.unlock();
        }
    }

    /*
     * Add new only new entry, if exist do not add
     * @param devId String device id
     * @param values, long[2] values
     * @return AppError, NO_SUCH if devId do not exists, INVALID for invalid params,
     * SUCCESS, ok
     *
    public AppError putMapEntry(String devId, long[] values){
        AppError err;

        err = checkId(devId);
        if(!err.equals(AppError.SUCCESS))
            return err;

        err = checkValues(values);
        if(!err.equals(AppError.SUCCESS))
            return err;

        // Add new values Multiple writters one reader
        this.devExpectedMap.putIfAbsent(devId,values);
        return AppError.SUCCESS;
    }*/

    /**
     * check string value
     * @param strDevId, String to check
     * @return AppError, NO_SUCH if devId do not exists, INVALID for invalid params,
     *  SUCCESS, ok
     */
    static public AppError checkId(String strDevId){
        DeviceService deviceService;
        DeviceId deviceId;

        deviceService = DefaultServiceDirectory.getService(DeviceService.class);

        try {
            deviceId = DeviceId.deviceId(strDevId);
            if(deviceService.getDevice(deviceId) == null)
                return AppError.NO_SUCH;
            else
                return AppError.SUCCESS;
        }
        catch (IllegalArgumentException e){
            return AppError.INVALID;
        }
    }

    /**
     * check long [] value
     * @param values, long[] vales
     * @return INVALID for invalid params, SUCCESS ok.
     */
    static public AppError checkValues(long[] values){
        if(values.length != 2)
            return AppError.INVALID;
        // TDO: agregar mas condiciones
        return AppError.SUCCESS;
    }

    /*
     * Update values for map
     * @param devId string
     * @param values long[2]
     * @return AppError, NO_SUCH if devId do not exists, INVALID for invalid params,
     * LOCKED of exists an entry for devId, SUCCESS, ok
     *
    public AppError replaceMapEntry(String devId, long[] values){
        AppError err;

        err = checkId(devId);
        if(!err.equals(AppError.SUCCESS))
            return err;

        err = checkValues(values);
        if(!err.equals(AppError.SUCCESS))
            return err;

        if(!this.devExpectedMap.containsKey(devId))
            return AppError.NO_SUCH;

        // Update values Multiple writters one reader
        this.devExpectedMap.replace(devId, values);
        return AppError.SUCCESS;
    }*/

    /*
     * Removes the mapping for devId from this map if present.
     * @param devId, whose mapping is to be removed from the map
     * @return AppError
     *
    public AppError removeMapEntry(String devId){
        AppError err;

        err = checkId(devId);
        if(!err.equals(AppError.SUCCESS))
            return err;

        if(!this.devExpectedMap.containsKey(devId))
            return AppError.NO_SUCH;

        // Remove values Multiple writters one reader
        this.devExpectedMap.remove(devId);
        return AppError.SUCCESS;
    }*/

    /**
     * Set new values from API
     * @param devExpectedMap new values
     */
    public void externalSetDevExpectedMap(ConcurrentHashMap<String, long[]> devExpectedMap) {
        writeLock.lock();
        try {
            this.devExpectedMap = devExpectedMap;
            this.localTables.replaceTable(this.devExpectedMap);
            updateTotalExpected();
        }
        catch (Exception e){
            log.error("error al acualizar from external map");
        }
        finally {
            writeLock.unlock();
        }
    }

    /**
     * update new values
     * @param statisticsDevMapDay new values
     */
    public AppError putEntryTable(HashMap<String, long[]> statisticsDevMapDay) {
        AppError err;
        writeLock.lock();
        try {
            if(devExpectedMap.isEmpty()){
                err = checkConsistent(statisticsDevMapDay, this.defaultExpectedMap);
            }
            else {
                err = checkConsistent(statisticsDevMapDay, this.devExpectedMap);
            }
            if (err.equals(AppError.SUCCESS)){
                this.localTables.updateTables(statisticsDevMapDay);
                this.devExpectedMap = getExpextedTotalForDevice(this.devExpectedMap);
                updateTotalExpected();
            }
            return err;
        }
        catch (Exception e){
            log.error("error al acualizar from internal map");
            return AppError.CONCURRENT_ERROR;
        }
        finally {
            writeLock.unlock();
        }
    }

    private AppError checkConsistent(HashMap<String, long[]> statisticsDevMapDay,
                                     ConcurrentHashMap<String, long[]> consistentMap){

        Set<String> keySet;

        if(statisticsDevMapDay == null){
            return AppError.NULL;
        }
        if(consistentMap.isEmpty()){
            return AppError.EMPTY;
        }
        if(statisticsDevMapDay.size() != consistentMap.size()){
            return AppError.INVALID;
        }

        keySet = consistentMap.keySet();

        for(String key : keySet){
            if(!statisticsDevMapDay.containsKey(key))
                return AppError.NO_SUCH;
        }

        return AppError.SUCCESS;
    }

    /**
     * ConcurrentHashMap Init Default values.
     * @return init map
     */
    private ConcurrentHashMap <String, long[]> initDefaultMap() {
        long []                 aux;
        ConcurrentHashMap <String, long[]> map;

        String[] distribDevs = {"of:0000000000000004", "of:0000000000000005",
                "of:0000000000000006", "of:0000000000000007"};

        map = new ConcurrentHashMap<>();

        for (String distribDev : distribDevs) {
            aux = new long[2];
            aux[DAY_COUNT] = INITIAL_COUNT / NUM_DEV_DSTR;
            aux[DAY_BYTES] = INITIAL_BYTES / NUM_DEV_DSTR;

            map.put(distribDev, aux);
        }
        return map;
    }


    public synchronized ConcurrentHashMap<String,long[]> getExpextedTotalForDevice(
            ConcurrentHashMap<String,long[]> oldExpectedForDevice){
        long []                 tmp;
        long []                 nuevo;
        Set<String>             keySet;
        ConcurrentHashMap<String,long[]> expectedCalc;
        keySet = oldExpectedForDevice.keySet();
        // StatisticsResources.getInstance().getDevExpectedMap().keySet();
        // Init new Expected Map
        expectedCalc = new ConcurrentHashMap<>();
        for (String device: keySet) {
            expectedCalc.put(device, new long[2]);
        }

        // Adder Reduction for every entry Map i every entry table
        for (Map<String, long[]> map: this.localTables.getTable()) {
            for (String device: keySet){
                nuevo = expectedCalc.get(device);
                tmp   = map.get(device);

                nuevo[DAY_COUNT] += tmp[DAY_COUNT];
                nuevo[DAY_BYTES] += tmp[DAY_BYTES];

                expectedCalc.replace(device, nuevo);
            }
        }
        return  expectedCalc;
    }


    //////////// USED BY STATISTICS //////

    public long[] getTotalExpexted() {
        readLock.lock();
        try{
            return this.totalExpexted;
        }
        finally {
            readLock.unlock();
        }
    }

    public long getExpectedForDevice(DeviceId deviceId, int var) {
        readLock.lock();
        try{
            if(var == DAY_BYTES || var == DAY_COUNT)
                return this.devExpectedMap.get(deviceId.toString())[var];
            else
                return -1;
        }
        finally {
            readLock.unlock();
        }
    }

    private void updateTotalExpected(){

        long [] total = new long[2];
        // Caluculate total expected value
        for (long[] value : this.devExpectedMap.values()) {
            total[DAY_COUNT] += value[DAY_COUNT];
            total[DAY_BYTES] += value[DAY_BYTES];
        }
        this.totalExpexted = total;
        log.info("Nuevo Total:{}", this.totalExpexted);
    }
}
