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

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.collect.Lists;
import com.google.common.collect.Lists;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.IPv4;
import org.onosproject.net.HostId;
import org.onosproject.store.AbstractStore;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.MapEvent;
import org.onosproject.store.service.MapEventListener;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.lang.Float;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.onos.byon.NetworkEvent.Type.*;

/**
 * Network Store implementation backed by consistent map.
 */
@Component(immediate = true)
@Service
public class DistributedNetworkStore
        // TODO Lab 6: Extend the AbstractStore class for the store delegate
        extends AbstractStore<NetworkEvent, NetworkStoreDelegate>
        implements NetworkStore {

    private static final int MAX_INDEX = 2000;

    private static Logger log = LoggerFactory.getLogger(DistributedNetworkStore.class);

    /*
     * TODO Lab 5: Get a reference to the storage service
     *
     * All you need to do is uncomment the following two lines.
     */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected StorageService storageService;

    /*
     * TODO Lab 5: Replace the ConcurrentMap with ConsistentMap
     */
    private Map<String, Set<HostId>> networks;

    private ConsistentMap<String, Set<HostId>> nets;

    //private Map<Integer, List<Double>> measure;
    private Map<Integer, Map<Integer, List<Double>>> measure;
    private ConsistentMap<Integer, Map<Integer, List<Double>>> mea;
    //private ConsistentMap<Integer, List<Double>> mea;
    private Map<Integer, Map<Integer, List<Double>>> iniMea = null;
    private Map<Integer, Integer> host2ip;
    private int ndev = 0;
    private int ndev2 = 0;
    private int cur_index = 1;
    //private String[] mea_file = new String[MAX_INDEX * 3 + 1];

    /*
     * TODO Lab 6: Create a listener instance of InternalListener
     *
     * You will first need to implement the class (at the bottom of the file).
     */
    private final InternalListener listener = new InternalListener();

    private final MeasureListener mListener = new MeasureListener();

    //private final Thread mUpdate = new Thread(new UpdateMeasurement());

    @Activate
    public void activate() {
        /**
         * TODO Lab 5: Replace the ConcurrentHashMap with ConsistentMap
         *
         * You should use storageService.consistentMapBuilder(), and the
         * serializer: Serializer.using(KryoNamespaces.API)
         */
        nets = storageService.<String, Set<HostId>>consistentMapBuilder()
                .withSerializer(Serializer.using(KryoNamespaces.API))
                .withName("byon-networks")
                .build();
        networks = nets.asJavaMap();

        mea = storageService.<Integer, Map<Integer, List<Double>>>consistentMapBuilder()
                .withSerializer(Serializer.using(KryoNamespaces.API))
                .withName("byon-measure")
                .build();
        measure = mea.asJavaMap();

        host2ip = Maps.newHashMap();
        iniMea = Maps.newHashMap();
        measure.clear();

        init_storage();

        /*
         * TODO Lab 6: Add the listener to the networks map
         *
         * Use nets.addListener()
         */
        nets.addListener(listener);
        mea.addListener(mListener);
        //mea.addListener(listener);
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        /*
         * TODO Lab 6: Remove the listener from the networks map
         *
         * Use nets.removeListener()
         */
        nets.removeListener(listener);

        mea.removeListener(mListener);

        measure.remove(0);
        iniMea.remove(0);

        iniMea = null;
        measure = null;
        mea = null;
        log.info("Stopped");
    }

    @Override
    public void putNetwork(String network) {
        networks.putIfAbsent(network, Sets.newHashSet());
    }

    @Override
    public void removeNetwork(String network) {
        networks.remove(network);
    }

    @Override
    public Set<String> getNetworks() {
        return ImmutableSet.copyOf(networks.keySet());
    }

    @Override
    public boolean addHost(String network, HostId hostId) {
        if (getHosts(network).contains(hostId)) {
            return false;
        }
        networks.computeIfPresent(network,
                                  (k, v) -> {
                                      Set<HostId> result = Sets.newHashSet(v);
                                      result.add(hostId);
                                      return result;
                                  });
        return true;
    }

    @Override
    public boolean removeHost(String network, HostId hostId) {
        if (!getHosts(network).contains(hostId)) {
            return false;
        }
        networks.computeIfPresent(network,
                                  (k, v) -> {
                                      Set<HostId> result = Sets.newHashSet(v);
                                      result.remove(hostId);
                                      return result;
                                  });
        return true;
    }

    @Override
    public Set<HostId> getHosts(String network) {
        return checkNotNull(networks.get(network), "Network %s does not exist", network);
    }

    /*
     * Hui Lin
     * Override measurement api
     * */
    @Override
    public void addDevice(int device){
        measure.get(0).putIfAbsent(device, Lists.newArrayList());
    }

    @Override
    public void removeDevice(String device){
        measure.remove(device);
    }

    @Override
    public Set<Integer> getDevices(){
        return ImmutableSet.copyOf(measure.keySet());
    }

    /*
    @Override
    public boolean addMeasure(String device, Double addMeasure){
        measure.computeIfPresent(device,
                (k, v) -> {
                    List<Double> result = Lists.newArrayList(v);
                    result.add(addMeasure);
                    return result;
                });
        return true;
    }
    */
    @Override
    public boolean updateMeasure(){
        //System.out.println("update measurement" + cur_index);
        //log.info("update measurement {}", cur_index);
        cur_index++;
        if (cur_index > MAX_INDEX) {
            cur_index = cur_index % MAX_INDEX;
        }
        //measure = new HashMap<Integer, List<Double>>(iniMea.get(cur_index));
        //measure.put(0, new HashMap<Integer, List<Double>>(iniMea.get(cur_index)));
        measure.put(0, iniMea.get(cur_index));
        return true;
    }

    @Override
    public boolean removeMeasure(int device, Double delMeasure){
        /*
        measure.computeIfPresent(device,
                (k, v) -> {
                    List<Double> result = Lists.newArrayList(v);
                    result.remove(delMeasure);
                    return result;
                });
                */
        return true;
    }

    @Override
    public Map<Integer, List<Double>> getMeasure(int index){
        if (index == 0 ) {
            if (measure.containsKey(0)) {
                return measure.get(0);
            } else {
                return null;
            }

        } else {
            return checkNotNull(iniMea.get(index), "Device %s does not exist", index);
        }
    }


    /*
     * TODO Lab 6: Implement an InternalListener class for remote map events
     *
     * The class should implement the MapEventListener interface and
     * its event method.
     */

    private class InternalListener implements MapEventListener<String, Set<HostId>> {
        @Override
        public void event(MapEvent<String, Set<HostId>> mapEvent) {
            final NetworkEvent.Type type;
            log.info("Hui Lin DEBUG 287");
            switch (mapEvent.type()) {
                case INSERT:
                    //log.info("mapevent insert 2");
                    type = NETWORK_ADDED;
                    break;
                case UPDATE:
                    //log.info("mapevent update 2");
                    type = NETWORK_UPDATED;
                    break;
                case REMOVE:
                    //log.info("mapevent remove 2");
                default:
                    //log.info("mapevent default 2");
                    type = NETWORK_REMOVED;
                    break;
            }
            notifyDelegate(new NetworkEvent(type, mapEvent.key()));
        }
    }

    private class MeasureListener implements MapEventListener<Integer, Map<Integer, List<Double>>> {

        @Override
        public void event(MapEvent<Integer, Map<Integer, List<Double>>> mapEvent) {
            final NetworkEvent.Type type;
            //NetworkEvent.Type type;
            //log.info("Hui Lin DEBUG 306");
            MapEvent.Type temp = MapEvent.Type.REMOVE;
            try {
                temp = mapEvent.type();
            } catch (Exception e){
                log.info(e.getMessage());
            }
            //log.info("Hui Lin DEBUG 312");

            switch (temp) {
                case INSERT:
                    log.info("mapevent insert");
                    type = NETWORK_ADDED;
                    break;
                case UPDATE:
                    //log.info("mapevent udpate");
                    type = NETWORK_UPDATED;
                    break;
                case REMOVE:
                    //log.info("mapevent remove");
                default:
                    log.info("mapevent default");
                    type = NETWORK_REMOVED;
                    break;
            }
            notifyDelegate(new NetworkEvent(type, Integer.toString(mapEvent.key())));
        }
    }

    /*
    private class UpdateMeasurement implements Runnable {
        public void run() {
            System.out.println("Hello from a thread!");
        }
    }
    */

    private void init_storage() {
        // obtain host to ip address
        int deviceIndex = 0;
        Charset charset = Charset.forName("US-ASCII");
        Path filePath = Paths.get("/local/hostip.txt");
        try (BufferedReader reader = Files.newBufferedReader(filePath, charset)) {
            String line = null;
            int row_count = 0;
            int row_count2 = 0;
            String deviceName = null;
            while ((line = reader.readLine()) != null) {
                //System.out.println(line);

                String[] parts = line.split(" ");

                if (parts.length != 2) {
                    log.warn("split errors");
                    return;
                }
                //System.out.println(parts[0] + " : " + parts[1]);
                //deviceIndex = Integer.parseInt(parts[0].substring(1));
                char first = parts[0].charAt(0);
                if (first != 'd') {
                    row_count2++;
                    String temp = parts[0].replaceAll("\\D+", "");
                    deviceIndex = Integer.parseInt(temp);
                    //System.out.println(deviceIndex);
                    host2ip.putIfAbsent(deviceIndex, IPv4.toIPv4Address(parts[1]));
                }
                row_count++;
            }
            ndev = row_count;
            ndev2 = row_count2;
            reader.close();
        } catch (IOException x) {
            //System.err.format("IOException: %s%n", x);
            log.warn("Can not open measurement file.");
        }
    }


    @Override
    public boolean addMeasure(String fileName) {
        int index = 0;
        Charset charset = Charset.forName("US-ASCII");
        Path filePath = Paths.get(fileName);


        try (BufferedReader reader = Files.newBufferedReader(filePath, charset)) {
            String line = null;
            int row_count = 1;
            int cur_index = 0;
            String deviceName = null;
            while ((line = reader.readLine()) != null) {
                if (row_count % 3 == 1) {
                    cur_index = Integer.parseInt(line);
                    iniMea.putIfAbsent(cur_index, Maps.newHashMap());
                }
                if (row_count % 3 != 1){
                    String[] parts = null;
                    parts = line.split(" ");
                    for(int loop1 = 0; loop1 < parts.length; loop1++){
                        iniMea.get(cur_index).putIfAbsent(loop1+1, Lists.newArrayList());
                        Double add_value = Double.parseDouble(parts[loop1]);
                        //System.out.println(Double.parseDouble(parts[loop1]));
                        iniMea.get(cur_index).computeIfPresent(loop1 + 1,
                                (k, v) -> {
                                    List<Double> result = Lists.newArrayList(v);
                                    result.add(add_value);
                                    return result;
                                });
                    }
                }
                row_count++;
                //System.out.println(row_count);
            }
            reader.close();
        } catch (IOException x) {
            //System.err.format("IOException: %s%n", x);
            log.warn("Can not open measurement file.");
            return false;
        }

        /*
        try (BufferedReader reader = Files.newBufferedReader(filePath, charset)) {
            //String line = null;
            int row_count = 1;
            String deviceName = null;
            while ((mea_file[row_count-1] = reader.readLine()) != null) {
                row_count++;
                //System.out.println(row_count);
            }
            reader.close();
        } catch (IOException x) {
            //System.err.format("IOException: %s%n", x);
            log.warn("Can not open measurement file.");
            return false;
        }

        System.out.println("begin copy");
        String[] parts = null;
        for (int i = 1; i <=2; i++){
            parts = mea_file[i].split(" ");
            //System.out.println(parts[0] + parts[1]);
            for(int loop1 = 0; loop1 < parts.length; loop1++){
                measure.putIfAbsent(loop1+1, Lists.newArrayList());
                Double add_value = Double.parseDouble(parts[loop1]);
                System.out.println(Double.parseDouble(parts[loop1]));
                measure.computeIfPresent(loop1 + 1,
                        (k, v) -> {
                            List<Double> result = Lists.newArrayList(v);
                            result.add(add_value);
                            return result;
                        });
            }
        }
        System.out.println("end copy");
        */


        //System.out.println("begin copy");
        /*
        for (Map.Entry<Integer, List<Double>> entry : iniMea.get(1).entrySet()) {
            measure.putIfAbsent(entry.getKey(), entry.getValue());
            //System.out.println(entry.getKey() + "/" + entry.getValue());
        }
        */

        System.out.println("Begin");
        Map<Integer, List<Double>> local = iniMea.get(1);
        log.info("initlized here");
        //measure.putIfAbsent(0, new HashMap<Integer, List<Double>>(iniMea.get(1)));
        measure.putIfAbsent(0, local);
        //measure = new HashMap<Integer, List<Double>>(iniMea.get(1));
        //measure.put(1, iniMea.get(1).get(1));
        //Double update_value  = iniMea.get(1).get(1).get(0);
        /*
        measure.computeIfPresent(1,

                (k, v) -> {
                    List<Double> result = Lists.newArrayList(v);
                    result.add(0, update_value);
                    return result;
                });
        */
        System.out.println("end");
        //System.out.println("end copy");


        /*
        measure.putIfAbsent(2, Lists.newArrayList());
        measure.computeIfPresent(2,
                (k, v) -> {
                    List<Double> result = Lists.newArrayList(v);
                    result.add(2.5);
                    return result;
                });
        */
        return true;
    }

}
