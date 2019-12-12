package org.gstesis.ddos.app.statistics;

import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.DeviceAnnotationConfig;

import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.Key;
import org.slf4j.Logger;

import java.util.List;
import java.util.Set;

import static java.lang.Thread.sleep;
import static org.gstesis.ddos.app.statistics.StatisticsResources.*;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * This class Change annotatio's device from any annotation to INSTPECT.
 * change it for WAIT_TIME time the return to original annotation
 * @see java.lang.Runnable
 */
public class Analizer implements Runnable {

    private static final int WAIT_TIME = 32171; // intervalo de tiempo 30s un primaso

    private IntentService        intentService;
    private NetworkConfigService netcfgService;

    private Set<DeviceId>        edgesDevIds;
    private List<Key>            deviatKeys;


    private final Logger log = getLogger(getClass());

    /**
     * Thread que Espera un dt para que el Ids analise el flujo
     * @param netcfgService, netcfgService epleado para el cambio de annotatios
     * @param intentService, para la bisqueda de los intents por key
     * @param IntentkeyList  lista de key para la eliminacion de los intents
     *
     * @see org.onosproject.net.config.NetworkConfigService
     * @see org.onosproject.net.intent.IntentService
     */
    public Analizer(NetworkConfigService netcfgService, IntentService intentService,
                    Set<DeviceId> edgesDevIds, List<Key> IntentkeyList) {

        this.intentService = intentService;
        this.netcfgService = netcfgService;
        this.deviatKeys    = IntentkeyList;
        this.edgesDevIds   = edgesDevIds;
    }

    /**
     * Change annotation temporarily WAIT_TIME time.
     */
    @Override
    public void run() {

        // Change Annotatios devs to STR_INSPECT
        edgesDevIds.forEach(objDevId -> changeAnnot(objDevId, STR_INSPECT));

        try {
            sleep(WAIT_TIME);
        }
        catch (Exception e) {
            log.info("Thread Interrupido abrutamente");
            return;
        }

        deviatKeys.forEach(key -> intentService.withdraw(this.intentService.getIntent(key)));

        // Became back Annotatios devs to STR_EDGES
        edgesDevIds.forEach(objDevId -> changeAnnot(objDevId, STR_EDGE));

        log.info("Intent/s 4003 eliminado/s, Retorno a EDGE");
    }

    /*
    private void bWLimit(){


        Band band = DefaultBand.builder()
                .ofType(Band.Type.DROP)
                .withRate(100L)
                .burstSize(0L)
                .build();
        MeterRequest meterReq = DefaultMeterRequest.builder()
                .forDevice(objDevId)
                .fromApp(appId)
                .withUnit(Meter.Unit.PKTS_PER_SEC)
                .withBands(Collections.singleton(band))
                .add();
        log.info("creado el limitador de banda--------------");

        Meter meter = meterService.submit(meterReq);
        log.info("submit ancho de banda----------");

        try {
            sleep(32171); // intervalo de tiempo 30s un primaso
        }
        catch (Exception e) {
            log.info("Thread Interrupido abrutamente");
            meterService.withdraw(meterReq, meter.id());
            return;
        }
        meterService.withdraw(meterReq, meter.id());
        log.info("eliminate---------------------");
    }
    */

    /**
     * Change Annotatios
     * @param deviceId, para el cambio de annotatios
     * @param value, nuevo valor del annotatios
     */
    private void changeAnnot(DeviceId deviceId, String value) {

        DeviceAnnotationConfig cfg;

        cfg = this.netcfgService.getConfig(deviceId, DeviceAnnotationConfig.class);

        if (cfg == null) {
            cfg = new DeviceAnnotationConfig(deviceId);
        }
        // add remove request config
        cfg.annotation(STR_ANNT, value);

        this.netcfgService.applyConfig(deviceId, DeviceAnnotationConfig.class, cfg.node());
    }
}
