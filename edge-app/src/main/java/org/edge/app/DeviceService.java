package org.edge.app;

import org.onosproject.event.ListenerService;
import org.onosproject.net.HostId;

/*
public class DeviceService {
}*/

public interface DeviceService extends ListenerService<NetworkEvent, NetworkListener> {

    //void updateConn();
    void removeEdgeRule();

}
