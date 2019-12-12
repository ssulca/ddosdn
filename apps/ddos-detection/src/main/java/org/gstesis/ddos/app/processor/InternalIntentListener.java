package org.gstesis.ddos.app.processor;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.intent.*;
import static org.onosproject.net.intent.IntentState.FAILED;
import static org.onosproject.net.intent.IntentState.WITHDRAWN;
import java.util.EnumSet;

public class InternalIntentListener  implements IntentListener {
    private static final EnumSet<IntentState> CAN_PURGE = EnumSet.of(WITHDRAWN, FAILED);

    private ApplicationId appId;
    private IntentService intentService;

    public InternalIntentListener(IntentService intentService, ApplicationId appId) {
        this.intentService = intentService;
        this.appId = appId;
    }

    @Override
    public synchronized void event(IntentEvent event) {

        Key key = event.subject().key();

        if (!appId.equals(event.subject().appId())) {
            // not my event, ignore
            return;
        }

        if (event.type() == IntentEvent.Type.WITHDRAWN || event.type() == IntentEvent.Type.FAILED) {
            if (CAN_PURGE.contains(intentService.getIntentState(key))) {
                intentService.purge(event.subject());
            }
        }
    }
}