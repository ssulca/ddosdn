/*
 * Copyright 2018-present Open Networking Foundation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.gstesis.mitigation.app;

import org.apache.felix.scr.annotations.*;

import org.onosproject.incubator.net.faultmanagement.alarm.AlarmId;
import org.onosproject.incubator.net.faultmanagement.alarm.AlarmProviderRegistry;
import org.onosproject.incubator.net.faultmanagement.alarm.AlarmProviderService;
import org.onosproject.incubator.net.faultmanagement.alarm.AlarmService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.packet.PacketService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.gstesis.mitigation.app.firewall.Firewall;
import org.gstesis.mitigation.app.server.SocketServerListener;

import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;
import static org.onlab.util.Tools.groupedThreads;
import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_REMOVED;

/**
 * ONOS application component. Esta APP permite instanciar un socket internet en
 * el controlador y recibir las alertas del Snort.
 * @author  Gaston Lopez
 * @author  Sergio Sulca
 */
@Component(immediate = true)
@Service
public class MitigationManager implements MitigationService{
    //Campos de la clase.
    private static final String APP_NAME = "org.gstesis.ddos.mitigation";
    private static final String INIT_MSG = ":: Started ::__DDoS-Mitigation__:: App";
    private static final String END_MSG  = ":: Stopped ::__DDoS-Mitigation__:: App";

    // Mensaje de rehabilitacion del ping.
    private static final String MSG_PING_REENABLED =
            "Re-habilitacion del ping sobre deviceID: {}";

    private final Logger log = getLogger(getClass()); // Logger.

    /////////////////////////////// ONOS Services ////////////////////////////
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService          coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService      flowRuleService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService        packetService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService          hostService; //allow find device ID de OVS.
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService        deviceService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected IntentService        intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected AlarmService          alarmService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected AlarmProviderRegistry alarmProviderRegistry;

    protected AlarmProviderService  alarmProviderService ;

    //////////////////////////// OUR variables /////////////////////////////
    // Firewall Singleton.
    private final ExecutorService socketListenerThread =
            Executors.newSingleThreadExecutor (groupedThreads("onos/apps/foo",
                    "foo-listener"));
    private final FlowRuleListener flowListener = new InternalFlowListener();

    protected TestProvider testProvider=null;
    // Utilizada para escribir las reglas del firewall.
    private ApplicationId appId;

    /**
     * Método llamado al activar la app en el controlador. .
     */
    @Activate
    protected void activate() {

        Firewall firewall;
        SocketServerListener ssListener; // Runnable.
        // Register App
        appId = coreService.registerApplication(APP_NAME);
        // Config Firewall
        try {
            testProvider = new TestProvider();
        }
        catch (Exception e){
            e.printStackTrace();
            log.error("falle test");
        }
        try {
            alarmProviderService = alarmProviderRegistry.register(testProvider);
        }
        catch (Exception e){
            e.printStackTrace();
            log.error("falle al registrarlo");
        }
        firewall = Firewall.getInstance();
        firewall.configFirewall (this.appId, this.flowObjectiveService , this.hostService,
                this.deviceService, this.intentService, this.alarmService,
                alarmProviderService);
        // Create Server INET Socket Listener
        ssListener = new SocketServerListener(firewall);

        flowRuleService.addListener  (flowListener); // Register FlowRule Event Listener
        socketListenerThread.execute (ssListener); // Run Server.
        log.info(INIT_MSG);
    }

    /**
     * Método llamado al desactivar la app en el controlador.
     */
    @Deactivate
    protected void deactivate() {

        socketListenerThread.shutdownNow(); //Desactivo el hilo.
        flowRuleService.removeFlowRulesById (appId);
        flowRuleService.removeListener (flowListener);
        alarmProviderRegistry.unregister(testProvider);
        log.info(END_MSG);
    }




    /**
     * Clase privada InternalFlowListener. Escucha reglas eliminadas. implements
     * FlowRuleListener
     */
    private class InternalFlowListener implements FlowRuleListener {

        /**
         * Método event. Detecta la remoción de un regla de esta app e imprime
         * un msje.
         * @param event FlowRuleEvent Es un evento que surge cuando se ejecutan
         *               acciones sobre las reglas.
         */
        public void event(FlowRuleEvent event) {
            Firewall firewall;
            FlowRule flowRule;

            firewall = Firewall.getInstance();
            flowRule = event.subject();

            // flowRule.selector().hashCode() + flowRule.treatment().hashCode()+;
            if (event.type() == RULE_REMOVED && flowRule.appId() == appId.id()) {
                firewall.removeRegistroRegla(flowRule.deviceId(), flowRule.selector());

                ////////////////////// REMOVER ID //////////////////////////////
                String uniqId = ""+flowRule.selector().hashCode()+flowRule.treatment().hashCode();
                alarmService.getAlarms(flowRule.deviceId()).forEach(alarm -> {
                    AlarmId tmpAlarmId = AlarmId.alarmId(flowRule.deviceId(), uniqId);
                    if(alarm.id().equals(tmpAlarmId))
                        alarmService.remove(alarm.id());
                });
                log.warn (MSG_PING_REENABLED, flowRule.deviceId());
            }
        }
    }

}
