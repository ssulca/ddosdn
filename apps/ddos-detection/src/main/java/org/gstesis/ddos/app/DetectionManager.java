/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.gstesis.ddos.app;

import org.apache.felix.scr.annotations.*;
import org.gstesis.ddos.app.processor.IdsResources;
import org.gstesis.ddos.app.processor.InternalIntentListener;
import org.gstesis.ddos.app.processor.ReactivePacketProcessor;
import org.gstesis.ddos.app.statistics.Statistics;
import org.gstesis.ddos.app.statistics.StatisticsResources;
import org.gstesis.ddos.app.statistics.UpgradeManager;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IpAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.IntentListener;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.Set;
import java.util.concurrent.*;

import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * This class consists in Intent mirror application, it forwards all the traffic to
 * destination and to a IDS host, via point to multipoint intents.
 * @author  Gaston Lopez
 * @author  Sergio Sulca
 */
@Component(immediate = true)
@Service
public class DetectionManager implements DetectionService{

    private static final String APP_NAME = "org.gstesis.ddos.detection";
    private static final String INIT_MSG = ":: Started ::__DDoS-Detection__:: App";
    private static final String END_MSG  = ":: Stopped ::__DDoS-Detection__:: App";

    private final Logger log = getLogger(getClass());

    /////////////////////////////// ONOS Services ////////////////////////////
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService          coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService      topologyService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService        packetService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected IntentService        intentService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService          hostService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService netcfgService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService        deviceService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected LinkService          linkService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private FlowObjectiveService   flowObjectiveService;

    // @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    // protected MeterService         meterService;
    // @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    // protected ComponentConfigService componentConfigService;

    ///////////////////////////// ONOS Property //////////////////////////////
    @Property(name = "intentNormalPri", intValue = 40001,
              label = "intent Normal Prioryty")
    private int intentNormalPri = 40001;
    @Property(name = "intentDDoslPri", intValue = 40003,
              label = "intent DDoS Priority")
    private int intentDDoslPri  = 40003;

    //////////////////////////// OUR variables /////////////////////////////
    private ReactivePacketProcessor processor; //procesado de paquetes
    private StatisticsResources     statisticsResources = null;
    private IntentListener          listener = null;
    // thread de ejecucion
    private final ExecutorService   executorServiceStats = Executors
        .newSingleThreadExecutor(groupedThreads("onos/apps/foo", "foo-stcs"));
    private final ExecutorService   executorServicUpdater = Executors
        .newSingleThreadExecutor(groupedThreads("onos/apps/foo", "foo-stcs"));

    /**
     * Activate App by ONOS
     */
    @Activate
    public void activate() {

        TrafficSelector.Builder selector;
        ApplicationId           appId;
        UpgradeManager          upgradeManager; // Runnable
        Statistics              statistics;     // Runnable.

        // TODO: mejorar Comportamiento registrando sus componentes
        // componentConfigService.registerProperties(getClass());

        appId     = coreService.registerApplication(APP_NAME);
        processor = new ReactivePacketProcessor(appId,
                hostService, topologyService, packetService, intentService,
                flowObjectiveService, intentNormalPri, intentDDoslPri);
        // Agrega el procesador espeficiado a la lista de procesadores
        packetService.addProcessor(processor, PacketProcessor.director(2));

        // Entidad selectora de trafico maneja una porcion del trafico de la red
        selector = DefaultTrafficSelector.builder();
        //asociacion con un tipo de trafico
        selector.matchEthType(Ethernet.TYPE_IPV4);

        // Solcita que los paqutes concidan con el selector en el plano de datos
        // Reactive baja prioridad solo se envia el trafico al controlador si los
        // paquetes no coiciden con las reglas.
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        statisticsResources = StatisticsResources.getInstance();

        // Intents WITDRAW delete
        listener   = new InternalIntentListener(intentService, appId);
        intentService.addListener(listener);

        // rennable object
        statistics = new Statistics(deviceService, linkService, topologyService,
                intentService, packetService, netcfgService, statisticsResources);
        executorServiceStats.execute(statistics); // Run runneable

        upgradeManager = new UpgradeManager(deviceService, linkService, statisticsResources);
        executorServicUpdater.execute(upgradeManager); //----------descomentar

        log.info(INIT_MSG);
    }

    /**
     * Deactivate App by ONOS
     */
    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(processor);
        processor.deleteIntents();
        processor = null;
        intentService.removeListener(listener);
        listener = null;
        executorServiceStats.shutdownNow(); // Desactivo el hilo.
        executorServicUpdater.shutdownNow(); //----------descomentar
        //updater = null;  ----------descomentar*/
        statisticsResources = null;
        log.info(END_MSG);
    }

    /**
     * retorna todos las ips configuradas existentes
     * @return IpAddressSer from IdsResources Singleton
     */
    @Override
    public Set<IpAddress> getIdsIpAddressSet(){
        // return IpAddressSer from IdsResources Singleton
        return IdsResources.getInstance().getIpAddressSet();
    }

}
