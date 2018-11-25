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
import com.google.common.collect.Iterables;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.AbstractListenerManager;
import org.onosproject.net.HostId;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.Key;
import org.quartz.*;
import org.quartz.impl.StdSchedulerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static java.lang.String.format;
import static org.quartz.JobBuilder.newJob;
import static org.quartz.SimpleScheduleBuilder.simpleSchedule;
import static org.quartz.TriggerBuilder.newTrigger;
//import static org.quartz.JobBuilder.newJob;
//import static org.quartz.SimpleScheduleBuilder.simpleSchedule;
//import static org.quartz.TriggerBuilder.newTrigger;



/**
 * BYON Application component.
 */
@Component(immediate = true)
@Service
public class NetworkManager
        extends AbstractListenerManager<NetworkEvent, NetworkListener>
        implements NetworkService {

    private static Logger log = LoggerFactory.getLogger(NetworkManager.class);

    private static final String HOST_FORMAT = "%s~%s";
    private static final String KEY_FORMAT = "%s,%s";

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkStore store;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected IntentService intentService;

    public static Map<Integer, List<Double>> global_measure;


    /* Hui Lin adding update measurement jobs
            * */
    /*
    JobDetail job = null;
    SimpleTrigger trigger = null;
    Scheduler sched = null;
    SchedulerFactory sf = null;
    */
    private static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static ScheduledExecutorService scheduler2 = Executors.newScheduledThreadPool(1);

    private static final int UPDATE_INTERVAL = ReactiveFwd.UPDATE_INTERVAL;

    /*
     * TODO Lab 6: Instantiate a NetworkStoreDelegate
     *
     * Using reference to the inherited 'post' method is sufficient.
     */
    private final NetworkStoreDelegate delegate = this::post;

    protected ApplicationId appId;

    @Activate
    protected void activate() throws SchedulerException {
        appId = coreService.registerApplication("org.onos.spoof", this::removeAllIntents);
        removeAllIntents();

        /*
         * TODO Lab 6: Remove delegate and event sink
         *
         * 1. Add the listener registry to the event dispatcher using eventDispatcher.addSink()
         * 2. Set the delegate in the store
         */
        eventDispatcher.addSink(NetworkEvent.class, listenerRegistry);
        store.setDelegate(delegate);

        /*
        job = newJob(SimpleJob.class).withIdentity("job1", "group1").build();
        trigger = (SimpleTrigger) newTrigger()
                .withIdentity("updateTrigger", "group1")
                .forJob("job1", "group1")
                .withSchedule(simpleSchedule().withIntervalInSeconds(5).withRepeatCount(SimpleTrigger.REPEAT_INDEFINITELY))
                .build();
        sf = new StdSchedulerFactory();
        sched = sf.getScheduler();
        */
        scheduler2.scheduleAtFixedRate(new UpdateGlobalMeasure(), 0,
                UPDATE_INTERVAL, TimeUnit.SECONDS);

        log.info("Started");
    }

    // Removes all intents as part of application being deactivated.
    private void removeAllIntents() {
        Iterables.filter(intentService.getIntents(), i -> Objects.equals(i.appId(), appId))
                .forEach(intentService::withdraw);
    }

    @Deactivate
    protected void deactivate() {
        /*
         * TODO Lab 6: Remove delegate and event sink
         *
         * 1. Remove the event class from the event dispatcher using eventDispatcher.removeSink()
         * 2. Unset the delegate from the store
         */
        eventDispatcher.removeSink(NetworkEvent.class);
        store.unsetDelegate(delegate);

        /*
        try {
            sched.shutdown();
        } catch (SchedulerException e) {
            e.printStackTrace();
        }
        */
        scheduler.shutdown();
        log.info("Stopped");
    }

    @Override
    public void createNetwork(String network) {
        checkNotNull(network, "Network name cannot be null");
        checkState(!network.contains(","), "Network names cannot contain commas");
        /*
         * TODO Lab 2: Add the network to the store
         */
        store.putNetwork(network);
        System.out.println("create networks");
    }

    @Override
    public void removeNetwork(String network) {
        checkNotNull(network, "Network name cannot be null");
        /*
         * TODO Lab 2: Remove the network from the store
         */
        store.removeNetwork(network);
        /*
         * TODO Lab 4: Remove the intents when the network is deleted
         */
        //removeIntents(network, null);
        System.out.println("remove networks");
    }

    @Override
    public Set<String> getNetworks() {
        /*
         * TODO Lab 2: Get the networks from the store and return them
         */
        return store.getNetworks();
    }

    @Override
    public void addHost(String network, HostId hostId) {
        checkNotNull(network, "Network name cannot be null");
        checkNotNull(hostId, "HostId cannot be null");
        /*
         * TODO Lab 2: Add the host to the network in the store
         *
         * TODO Lab 3: Connect the host to the network using intents -- addIntents()
         *     You only need to add the intents if this is the first time that
         *     the host is added. (Check the store's return value)
         */

        boolean hostWasAdded = store.addHost(network, hostId);
        if (hostWasAdded) {
            //addIntents(network, hostId, store.getHosts(network));
            System.out.println("a host is added to networks");
        }
    }

    @Override
    public void removeHost(String network, HostId hostId) {
        checkNotNull(network, "Network name cannot be null");
        checkNotNull(hostId, "HostId cannot be null");
        /*
         * TODO Lab 2: Remove the host from the network in the store
         *
         * TODO Lab 4: Remove the host's intents from the network
         */
        boolean hostWasRemoved = store.removeHost(network, hostId);
        if (hostWasRemoved) {
            //removeIntents(network, hostId);
            System.out.println("a host is removed from networks");
        }
    }

    @Override
    public Set<HostId> getHosts(String network) {
        checkNotNull(network, "Network name cannot be null");
        /*
         * TODO Lab 2: Retrieve the hosts from the store and return them
         */
        return store.getHosts(network);
    }

    /**
     * Adds an intent between a new host and all others in the network.
     *
     * @param network    network name
     * @param src        the new host
     * @param hostsInNet all hosts in the network
     */
    private void addIntents(String network, HostId src, Set<HostId> hostsInNet) {
        /*
         * TODO Lab 3: Implement add intents
         *
         * 1. Create a HostToHostIntent intent between src and every other host in
         *    the network using HostToHostIntent.builder()
         * 2. Generate the intent key using generateKey(), so they can be removed later
         * 3. Submit the intents using intentService.submit()
         */
        hostsInNet.forEach(dst -> {
            if (!src.equals(dst)) {
                Intent intent = HostToHostIntent.builder()
                        .appId(appId)
                        .key(generateKey(network, src, dst))
                        .one(src)
                        .two(dst)
                        .build();
                intentService.submit(intent);
            }
        });
    }

    /**
     * Removes intents that involve the specified host in a network.
     *
     * @param network network name
     * @param hostId  host to remove; all hosts if null
     */
    private void removeIntents(String network, HostId hostId) {
        /*
         * TODO Lab 4: Implement remove intents
         *
         * 1. Get the intents from the intent service using intentService.getIntents()
         * 2. Using matches() to filter intents for this network and hostId
         * 3. Withdrawn intentService.withdraw()
         */
        Iterables.filter(intentService.getIntents(), i -> matches(network, hostId, i))
                .forEach(intentService::withdraw);
    }

    /**
     * Returns ordered intent key from network and two hosts.
     *
     * @param network network name
     * @param one     host one
     * @param two     host two
     * @return canonical intent string key
     */
    protected Key generateKey(String network, HostId one, HostId two) {
        String hosts = one.toString().compareTo(two.toString()) < 0 ?
                format(HOST_FORMAT, one, two) : format(HOST_FORMAT, two, one);
        return Key.of(format(KEY_FORMAT, network, hosts), appId);
    }

    /**
     * Matches an intent to a network and optional host.
     *
     * @param network network name
     * @param hostId  optional host id, wildcard if null
     * @param intent  intent to match
     * @return true if intent matches, false otherwise
     */
    protected boolean matches(String network, HostId hostId, Intent intent) {
        if (!Objects.equals(appId, intent.appId())) {
            // different app ids
            return false;
        }

        String key = intent.key().toString();
        if (!key.startsWith(network)) {
            // different network
            return false;
        }

        if (hostId == null) {
            // no host id specified; wildcard match
            return true;
        }

        String[] fields = key.split(",");
        // return result of id match in host portion of key
        return fields.length > 1 && fields[1].contains(hostId.toString());
    }
    /**
     * Hui Lin
     */
    public void addMeasure(String fileName){


        //store.addDevice("1");
        //store.addMeasure("1", 1.1);
        //store.addMeasure("1", 1.2);
        store.addMeasure(fileName);


        System.out.println("Add measurements");
    }
    public void updateMeasure() throws Exception {
        //store.updateMeasure();

        System.out.println("entering NetworkManager updateMeasure");
        //UpdateTrigger example = new UpdateTrigger();
        //example.run();
        /*
        Date ft = sched.scheduleJob(job, trigger);
        sched.start();
        */
        scheduler.scheduleAtFixedRate(new MyRunnableTask(), 0,
                ReactiveFwd.UPDATE_INTERVAL, TimeUnit.SECONDS);

    }
    public void getMeasure(int index){
        /*
        Set<String> devices = store.getDevices();
        for (String s : devices){
            System.out.format("h" + s + ": ");
            List<Double> values = store.getMeasure(s);
            for (Double f : values){
                System.out.format("%f ", f);
            }
            System.out.format(" %n");
        }
        */
        Map<Integer, List<Double>> cur_measure = store.getMeasure(index);
        System.out.println(cur_measure.toString());
    }


    /*
    private class UpdateTrigger {
        public void run() throws Exception {

            JobDetail job = null;
            SimpleTrigger trigger = null;
            Scheduler sched = null;
            SchedulerFactory sf = null;

            job = newJob(SimpleJob.class).withIdentity("job1", "group1").build();
            trigger = (SimpleTrigger) newTrigger()
                    .withIdentity("updateTrigger", "group1")
                    .forJob("job1", "group1")
                    .withSchedule(simpleSchedule().withIntervalInSeconds(5).withRepeatCount(SimpleTrigger.REPEAT_INDEFINITELY))
                    .build();
            sf = new StdSchedulerFactory();
            sched = sf.getScheduler();
            Date ft = sched.scheduleJob(job, trigger);
            sched.start();
            System.out.println("running ?");
            log.info("running ?");
            try {
                // wait 33 seconds to show jobs
                Thread.sleep(30L * 1000L);
                // executing...
            } catch (Exception e) {
                //
            }

            sched.shutdown();

        }
    }
    */

    //public void updateConn(){
    //    log.info("network manager update conn");
    //}

    private class MyRunnableTask implements Runnable {

        @Override
        public void run() {
            //System.out.println("running once for a thread");
            //log.info("running in a thread");
            //global_measure = store.getMeasure(0);
            store.updateMeasure();
        }
    }

    private class UpdateGlobalMeasure implements Runnable {

        @Override
        public void run() {
                global_measure = store.getMeasure(0);
        }
    }



}
