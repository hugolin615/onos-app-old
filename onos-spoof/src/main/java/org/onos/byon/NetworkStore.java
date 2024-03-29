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

import org.onosproject.net.HostId;
import org.onosproject.store.Store;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tracks networks and their hosts.
 */
public interface NetworkStore
        // TODO Lab 6: Extend Store<NetworkEvent, NetworkStoreDelegate>
        extends Store<NetworkEvent, NetworkStoreDelegate>
{
    /**
     * Create a named network.
     *
     * @param network network name
     */
    void putNetwork(String network);

    /**
     * Removes a named network.
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
     * @return true if the host was added; false if it already exists
     */
    boolean addHost(String network, HostId hostId);

    /**
     * Removes a host from the given network.
     *
     * @param network network name
     * @param hostId  host id
     * @return true if the host was removed; false if it was already gone
     */
    boolean removeHost(String network, HostId hostId);

    /**
     * Returns all the hosts in a network.
     *
     * @param network network name
     * @return set of host ids
     */
    Set<HostId> getHosts(String network);

    /*
     * Hui Lin
     * added interface for adding/remvoing measurement for each device
     */

    void addDevice(int device);
    void removeDevice(String device);
    Set<Integer> getDevices();
    //boolean addMeasure(String device, Double addMeasure);
    boolean addMeasure(String fileName);
    boolean removeMeasure(int device, Double delMeasure);
    boolean updateMeasure();
    Map<Integer, List<Double>> getMeasure(int index);

}
