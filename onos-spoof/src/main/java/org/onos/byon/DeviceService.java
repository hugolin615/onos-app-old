package org.onos.byon;

import org.onosproject.event.ListenerService;
import org.onosproject.net.HostId;

import java.util.Set;

/**
 * Created by hugo on 8/29/16.
 */
public interface DeviceService extends ListenerService<NetworkEvent, NetworkListener> {


    void updateConn();

}
