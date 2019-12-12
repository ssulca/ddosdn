package org.gstesis.ddos.app.statistics;

import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Link;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.link.LinkService;
import org.slf4j.Logger;

import java.util.HashSet;
import java.util.Set;

/**
 * Monitor Interface
 * @see org.slf4j.Logger
 * @see org.onosproject.net.device.DeviceService
 * @see org.onosproject.net.link.LinkService
 */
public interface Monitoring {
    String ANNT  = "killa";
    String EDGE  = "edge";

    /**
     * Metodo retorna un conjunto con los devices identifiacados por annotatios
     * @param annot String anontation que identifca la caracteristica
     * @return a Set con los devicesId
     */
    default Set<DeviceId> getDevIdsByAnnot(DeviceService deviceService, String annot, Logger log){
        Set<DeviceId>     deviceIds;
        Iterable <Device> availableDevices;

        deviceIds = new HashSet<>();
        //get sw disponibles
        availableDevices = deviceService.getAvailableDevices(Device.Type.SWITCH);
        for (Device dev : availableDevices){
            /* busqueda de las anotaciones si no existe no se agrega al conjunto */
            try {
                if (dev.annotations().value(ANNT).equals(annot)) {
                   deviceIds.add(dev.id());
                   //log.info("dev {}:{}",annot,dev.id().toString());
                }
            }
            catch (NullPointerException e){
               log.error("No se encuentran las anotaciones :dev{}", dev.id().toString());
            }
        }
        return deviceIds;
     }

    /**
     * Retorna Conjunto de los PortStatistics de los puertos conectados a los edges
     * @param devId DeviceId del disposivo del cual se quiere obtener las estadisticas
     *             delta cada 10s
     * @return a Set con todos los PortStatics
     */
    default Set<PortStatistics> getStatisticsEdgePorts(DeviceService deviceService,
                                                       LinkService linkService,
                                                       DeviceId devId , Logger log ){
        Device dev ;
        Set<PortStatistics> portSet;

        portSet = new HashSet<>();
        //se obtienen todos los links conectado al dispostivo
        Set<Link> ingressLinks = linkService.getDeviceIngressLinks(devId);
        //busqueda en los enlaces, buscado conexiones con los edges
        for (Link link: ingressLinks) {
            dev = deviceService.getDevice(link.src().deviceId());
            try {
                if (dev.annotations().value(ANNT).equals(EDGE)) {
                    // True: se agrega la estadistica del puerto.
                    //log.info("dev/port: {}/{}",devId,link.dst().port()); //cometar
                    portSet.add(deviceService.getDeltaStatisticsForPort(devId, link.dst().port()));
                }
            }
            catch (NullPointerException e){
                log.error("No se encuentran las anotaciones EDGE :dev{}",dev.id().toString());
            }
        }
        return portSet;
    }

    /**
     * Get all "EDGE" device connected to "DISTRIBTION" device
     * @param deviceService, DeviceService
     * @param linkService, LinkService
     * @param devId, "DISTRIBTION" deviceID
     * @param log, Logger
     * @return Set<DeviceId> "EDGE" devices Set
     */
    default Set<DeviceId> getEdgesConnected(DeviceService deviceService, LinkService linkService,
                                            DeviceId devId , Logger log ){
        Device dev ;
        Set<DeviceId> edgeSet;

        edgeSet = new HashSet<>();
        //se obtienen todos los links conectado al dispostivo
        Set<Link> ingressLinks = linkService.getDeviceIngressLinks(devId);
        //busqueda en los enlaces, buscado conexiones con los edges
        for (Link link: ingressLinks) {
            dev = deviceService.getDevice(link.src().deviceId());
            try {
                if (dev.annotations().value(ANNT).equals(EDGE)) {
                    /* True: se agrega la estadistica del puerto. */
                    //log.info("dev/port: {}/{}",devId,link.dst().port()); //cometar
                    edgeSet.add(dev.id());
                }
            }
            catch (NullPointerException e){
                log.error("No se encuentran las anotaciones EDGE :dev{}",dev.id().toString());
            }
        }
        return edgeSet;
    }

    /**
     * Get first EDGE device conetect to DISTRIBUTION device with next parameters
     * @param deviceService DeviceService
     * @param linkService LinkService
     * @param devId DISTRIBUTION DeviceId
     * @param portNumber DISTRIBUTION deviceId port conect
     * @param log Logger
     * @return EDGE device ID.
     */
    default DeviceId getEdgeConnected(DeviceService deviceService, LinkService linkService,
                                       DeviceId devId , PortNumber portNumber, Logger log ){
        Device dev ;
        Set<Link> ingressLinks;

        // se obtienen todos los links conectado al dispostivo
        ingressLinks = linkService.getDeviceIngressLinks(devId);
        //busqueda en los enlaces, buscado conexiones con los edges
        for (Link link: ingressLinks) {
            if(link.dst().port().equals(portNumber)) {
                dev = deviceService.getDevice(link.src().deviceId());
                try {
                    if (dev.annotations().value(ANNT).equals(EDGE)) {
                        // True: se agrega la estadistica del puerto.
                        //log.info("dev/port: {}/{}",devId,link.dst().port()); //cometar
                        return dev.id();
                    }
                } catch (NullPointerException e) {
                    log.error("No se encuentran las anotaciones EDGE :dev{}", dev.id().toString());
                }
            }
        }
        return null;
    }


    /**
     * Retorna Conjunto de los PortStatistics de los puertos conectados a los edges
     * @param devId DeviceId del disposivo del cual se quiere obtener las estadisticas Totales
     * @return a Set con todos los PortStatics
     */
    default Set<PortStatistics> getStatisticsEdgePortsTotal(DeviceService deviceService,
                                                            LinkService linkService,
                                                            DeviceId devId , Logger log ){
        Device dev ;
        Set<PortStatistics> portSet;

        portSet = new HashSet<>();
        //se obtienen todos los links conectado al dispostivo
        Set<Link> ingressLinks = linkService.getDeviceIngressLinks(devId);
        //busqueda en los enlaces, buscado conexiones con los edges
        for (Link link: ingressLinks) {
            dev = deviceService.getDevice(link.src().deviceId());
            try {
                if (dev.annotations().value(ANNT).equals(EDGE)) {
                    /* True: se agrega la estadistica del puerto. */
                    //log.info("dev/port: {}/{}",devId,link.dst().port()); //cometar
                    portSet.add(deviceService.getStatisticsForPort(devId, link.dst().port()));
                }
            }
            catch (NullPointerException e){
                log.error("No se encuentran las anotaciones :dev{}", dev.id().toString());
            }
        }
        return portSet;
    }
}
