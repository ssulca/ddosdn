package org.gstesis.mitigation.app;

import org.onosproject.incubator.net.faultmanagement.alarm.AlarmProvider;
import org.onosproject.net.DeviceId;
import org.onosproject.net.MastershipRole;
import org.onosproject.net.provider.AbstractProvider;
import org.onosproject.net.provider.ProviderId;

/**
 * Provider to implement Alarm Service Provider
 * @see org.onosproject.net.provider.Provider
 * @see org.onosproject.net.provider.AbstractProvider
 * @see org.onosproject.incubator.net.faultmanagement.alarm.AlarmProvider
 */
public class TestProvider extends AbstractProvider implements AlarmProvider {

    public static final ProviderId PID = new ProviderId("of", "socket");

    private DeviceId deviceReceived;
    private MastershipRole roleReceived;

    /**
     * Create and Register new Provider
     * @see org.onosproject.net.provider.Provider
     */
    public TestProvider() {
        super(PID);
    }

    @Override
    public void triggerProbe(DeviceId deviceId) {
    }
}