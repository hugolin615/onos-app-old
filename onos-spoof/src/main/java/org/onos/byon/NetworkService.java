/*
 * Copyright 2015 Open Networking Laboratory
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

package org.onos.byon;

import org.onosproject.event.ListenerService;
import org.onosproject.net.HostId;

import java.util.List;
import java.util.Set;

/**
 * Service that allows to create virtual named networks
 * which provide mesh connectivity between hosts of a
 * given network.
 */
public interface NetworkService extends ListenerService<NetworkEvent, NetworkListener> {

    /**
     * Create a named network.
     *
     * @param network network name
     */
    void createNetwork(String network);

    /**
     * Deletes a named network.
     *
     * @param network network name
     */
    void removeNetwork(String network);

    /**
     * Returns a set of network names.
     *
     * @return a set of network names
     */
    Set<String> getNetworks();

    /**
     * Adds a host to the given network.
     *
     * @param network network name
     * @param hostId  host id
     */
    void addHost(String network, HostId hostId);

    /**
     * Removes a host from the given network.
     *
     * @param network network name
     * @param hostId  host id
     */
    void removeHost(String network, HostId hostId);

    /**
     * Returns all the hosts in a network.
     *
     * @param network network name
     * @return set of host ids
     */
    Set<HostId> getHosts(String network);

    /**
     * Hui Lin
     * update measurements (background thread periodically add
     * measurements from a file)
     */
    void addMeasure(String fileName);
    void updateMeasure() throws Exception;
    void getMeasure(int index);
    //void updateConn();

}
