package org.gstesis.ddos.app;

import org.onlab.packet.IpAddress;

import java.util.Set;

public interface DetectionService {

    Set<IpAddress> getIdsIpAddressSet();

}
