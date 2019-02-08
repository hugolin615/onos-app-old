package org.edge.app;

import org.onosproject.event.AbstractEvent;


/*
public class NetworkEvent {
}*/

public class NetworkEvent extends AbstractEvent<NetworkEvent.Type, String> {

    enum Type {
        NETWORK_ADDED,
        NETWORK_REMOVED,
        NETWORK_UPDATED
    }

    public NetworkEvent(Type type, String subject) {
        super(type, subject);
    }
}
