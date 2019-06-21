/*
 * Copyright 2014 Open Networking Foundation
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
package org.onosproject.ifwd;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.TCP;
import org.onlab.packet.IPacket;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.IntentState;
import org.onosproject.net.intent.Key;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.EnumSet;

import static org.slf4j.LoggerFactory.getLogger;


//import org.onosproject.net.PortNumber;
import org.onlab.packet.IPv4;
import org.onosproject.net.DeviceId;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Random;
//import com.google.common.collect.Maps;
//import com.google.common.collect.Lists;
//import java.util.Calendar;
//import java.util.Date;
//import java.time.ZonedDateTime;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.IOException;

/**
 * WORK-IN-PROGRESS: Sample reactive forwarding application using intent framework.
 */
@Component(immediate = true)
public class IntentReactiveForwarding {

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private ApplicationId appId;

    private static final int DROP_RULE_TIMEOUT = 300;

    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
                                                                            IntentState.WITHDRAWING,
                                                                            IntentState.WITHDRAW_REQ);

    ////// Hui Lin
    private static final int DEFAULT_DNP3_PORT = 20000;
    private static final int RELAY_IP = 0x0A00000C;
    private static final int CC_IP = 0x0A000003;
    private static final int FAKE_IP = 0x0A000002;
    private static final int SWITCH_LAT_EN = 0;
    private static final int SWITCH_LAT_AVE = 20;  // in milliseconds
    private static final int SWITCH_LAT_STDEV = 5; // in milliseconds
    private static final int MAX_BUF = 1000;
    private Map<String, Map<String, PortNumber>> mac2port;
    private Map<String, Map<Integer, PortNumber>> ip2port;
    private Map<Integer, Integer> ip2host;
    //private Map<Integer, Long> ackCache;
    private Map<Integer, Map<Integer, Long>> ackCache;
    private Map<Integer, Map<Integer, Integer>> fcCache;
    //private List<Long> ackLat;
    private Map<Integer, List<Long>> appLat;
    private Map<Integer, List<Long>> fakeLat; // sometimes fake latency can be quicker
    private Random ran;
    private int appCount;
    private int fakeCount;
    //private Date date;

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.app.spoofsingle2");

        packetService.addProcessor(processor, PacketProcessor.director(2));

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        //mac2port = Maps.newHashMap();
        //ip2port = Maps.newHashMap();
        mac2port = new HashMap<String, Map<String, PortNumber>>();
        ip2port = new HashMap<String, Map<Integer, PortNumber>>();
        //ackCache = new HashMap<Integer, Long>();
        ackCache = new HashMap<Integer, Map<Integer, Long>>();
        fcCache = new HashMap<Integer, Map<Integer, Integer>>();
        appLat = new HashMap<Integer, List<Long>>();
        fakeLat = new HashMap<Integer, List<Long>>();
        ran = new Random();
        appCount = 0;
        fakeCount = 0;
        //date = new Date();

        log.info("Started");
    }

    @Deactivate
    public void deactivate() {

        // record the appLat and fakeLat
        try {
            FileWriter fileWriter = new FileWriter("/home/hugo/OfflineResult/190424_Spoof/sdn.log");
            PrintWriter printWriter = new PrintWriter(fileWriter);

            printWriter.printf("real device\n");
            for (Integer fc : appLat.keySet()) {
                printWriter.printf("%d\n", fc);
                for (int i = 0; i < appLat.get(fc).size(); i++) {
                    printWriter.printf("%d ", appLat.get(fc).get(i));
                }
            }
            printWriter.printf("\n");

            printWriter.printf("fake device\n");

            for (Integer fc : fakeLat.keySet()) {
                printWriter.printf("%d\n", fc);
                for (int i = 0; i < fakeLat.get(fc).size(); i++) {
                    printWriter.printf("%d ", fakeLat.get(fc).get(i));
                }
            }
            printWriter.close();
            fileWriter.close();
        } catch (IOException e) {
            System.out.println("File write exception");
        }

        packetService.removeProcessor(processor);
        processor = null;
        mac2port = null;
        ip2port = null;
        ackCache = null;
        fcCache = null;
        appLat = null;
        fakeLat = null;
        ran = null;
        //date = null;
        log.info("Stopped");
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {

        // CHECKSTYLE IGNORE MethodLength FOR NEXT 300 LINES
        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            PortNumber outport;
            IPv4 ipv4Packet;
            //TCP tcpPacket;
            //int tcpDstPort = 0;
            //int tcpSrcPort = 0;

            if (ethPkt == null) {
                return;
            }

            HostId srcId = HostId.hostId(ethPkt.getSourceMAC());
            HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
            String srcIdStr = srcId.toString();
            String dstIdStr = dstId.toString();
            DeviceId dpid = pkt.receivedFrom().deviceId();
            String dpidStr = dpid.toString();
            PortNumber inport = pkt.receivedFrom().port();

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                //log.info("ip2port {}", ip2port.get(dpidStr));
                //log.info("measurements {}", NetworkManager.global_measure);
                ipv4Packet = (IPv4) ethPkt.getPayload();

            } else {
                //context.treatmentBuilder().setOutput(PortNumber.FLOOD);
                //context.send();
                //log.info("non ip packet flood");
                packetOut(context, PortNumber.FLOOD);
                return;
            }

            // Bail if this is deemed to be a control packet.
            //if (isControlPacket(ethPkt)) {
            //    return;
            //}

            Integer srcIp = ipv4Packet.getSourceAddress();
            Integer dstIp = ipv4Packet.getDestinationAddress();

            mac2port.putIfAbsent(dpidStr, new HashMap<String, PortNumber>());
            ip2port.putIfAbsent(dpidStr, new HashMap<Integer, PortNumber>());
            //switchCount.putIfAbsent(dpidStr, 0);

            // I did not use it
            Map<String, PortNumber> temp = mac2port.get(dpidStr);
            if (!temp.containsKey(srcIdStr)) {
                if (temp.containsKey(dstIdStr)) {
                    PortNumber tempPort = temp.get(dstIdStr);
                    if (!tempPort.equals(inport)) {
                        temp.put(srcIdStr, inport);
                    }
                } else {
                    temp.putIfAbsent(srcIdStr, inport);
                }
            }

            Map<Integer, PortNumber> temp1 = ip2port.get(dpidStr);

            if (!temp1.containsKey(srcIp)) {
                if (temp1.containsKey(dstIp)) {
                    PortNumber tempPort = temp1.get(dstIp);
                    if (!tempPort.equals(inport)) {
                        temp1.putIfAbsent(srcIp, inport);
                        ip2port.get(dpidStr).putIfAbsent(srcIp, inport);
                    }
                } else {
                    //if (host2ip.containsValue(srcIp)) {
                    if ((srcIp - IPv4.toIPv4Address("10.0.0.1")) <= 65535) {
                        temp1.putIfAbsent(srcIp, inport);
                        ip2port.get(dpidStr).putIfAbsent(srcIp, inport);
                    }
                }
            }

            if (temp1.containsKey(dstIp)) {
                outport = temp1.get(dstIp);
            } else {
                outport = PortNumber.FLOOD;
                //log.info("Hui Lin cannot decide outbound port.");
                //log.info("Hui Lin Return:476 {}", System.currentTimeMillis() - curTime);
                //log.info("{}:  ", dpidStr);
                for (Integer key : temp1.keySet()) {
                    //System.out.println(key + " " + temp.get(key).toString());
                    //log.info("{} -> {} ", key, temp1.get(key));
                }
            }

            // cache the ack of the DNP3 request
            if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                //log.info("Hui Lin found TCP");
                long switchLat = 0;
                if (SWITCH_LAT_EN == 1) {
                    switchLat = (long) ran.nextGaussian() * SWITCH_LAT_STDEV + SWITCH_LAT_AVE;
                }

                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                int tcpSrcPort = tcpPacket.getSourcePort();
                int tcpDstPort = tcpPacket.getDestinationPort();

                // cache the time of the request
                //if ((dstIp == RELAY_IP) && (srcIp == CC_IP) && (tcpDstPort == DEFAULT_DNP3_PORT)) {
                if ((srcIp == CC_IP) && (tcpDstPort == DEFAULT_DNP3_PORT)) {
                    IPacket dnp3P = tcpPacket.getPayload();
                    byte[] dnp3B = dnp3P.serialize();
                    //log.info("Hui Lin found DNP3 request {} {}", dnp3B, dnp3B.length);
                    if (dnp3B.length >= 13) {
                        byte dnp3fc = dnp3B[12];
                        int dnp3fc2 = dnp3fc;
                        //log.info("Hui Lin found DNP3 request 2 {}", dnp3fc);
                        //if (dnp3fc == 0x01) {
                        if (true) {
                            int tcpAck = tcpPacket.getAcknowledge();
                            //long timeMilli = date.getTime();
                            long timeMilli = System.currentTimeMillis();
                            //log.info("Hui Lin cache DNP3 request time {}", timeMilli);
                            ackCache.putIfAbsent(dstIp, new HashMap<Integer, Long>());
                            ackCache.get(dstIp).put(tcpAck, timeMilli);
                            fcCache.putIfAbsent(dstIp, new HashMap<Integer, Integer>());
                            fcCache.get(dstIp).put(tcpAck, dnp3fc2);
                        }
                    }
                }
                // calculate the latency of ack and responses from real device
                if ((srcIp == RELAY_IP) && (dstIp == CC_IP)) {
                    // simulate switch latency
                    log.info("Hui Lin found DNP3 responses");
                    IPacket dnp3P = tcpPacket.getPayload();
                    byte[] dnp3B = dnp3P.serialize();
                    if (dnp3B.length > 0) {
                        int tcpSeq = tcpPacket.getSequence();
                        log.info("Hui Lin found DNP3 responses 2");
                        if (ackCache.containsKey(srcIp)) {
                            if (ackCache.get(srcIp).containsKey(tcpSeq)) {
                                //long timeMilli = date.getTime();
                                long timeMilli = System.currentTimeMillis();
                                log.info("Hui Lin response time {} {}",
                                        timeMilli, ackCache.get(srcIp).get(tcpSeq));
                                long curLat = timeMilli - ackCache.get(srcIp).get(tcpSeq);
                                int curFC = fcCache.get(srcIp).get(tcpSeq);

                                appLat.putIfAbsent(curFC, new ArrayList<Long>());
                                appLat.get(curFC).add(curLat);
                                //if ((appLat.size() % 10) == 1) {
                                //    log.info("Hui Lin appLat {}", appLat);
                                //}
                                if (appLat.get(curFC).size() > MAX_BUF) {
                                    appLat.get(curFC).remove(0);
                                }
                                if (fakeLat.containsKey(curFC)) {
                                    if (fakeLat.get(curFC).size() > 0) {
                                        long curFakeLat = fakeLat.get(curFC).get(appCount);
                                        appCount = (appCount + 1) % (fakeLat.get(curFC).size());
                                        log.info("real latency {} fake latency {}",
                                                curLat, curFakeLat);
                                        if (curLat < curFakeLat) {
                                            //long start = date.getTime();
                                            //long start = date.getTime();
                                            //long end = 0;
                                            long delay = curFakeLat - curLat;
                                            try {
                                                //Thread.sleep(delay);
                                                Thread.sleep(switchLat + delay);
                                            } catch (InterruptedException e) {
                                                System.out.println("Sleep exception.");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // adjust the latency
                if ((srcIp == FAKE_IP) && (dstIp == CC_IP)) {
                    //log.info("Hui Lin found DNP3 response from {}", srcIp);
                    IPacket dnp3P = tcpPacket.getPayload();
                    byte[] dnp3B = dnp3P.serialize();
                    if (dnp3B.length > 0) {
                        int tcpSeq = tcpPacket.getSequence();
                        //log.info("Hui Lin found DNP3 response 2 from {}", srcIp);
                        if (ackCache.containsKey(srcIp)) {
                            log.info("Hui Lin has fake ack cached");
                            if (ackCache.get(srcIp).containsKey(tcpSeq)) {
                                //long timeMilli = date.getTime();
                                long timeMilli = System.currentTimeMillis();
                                long curLat = timeMilli - ackCache.get(srcIp).get(tcpSeq);

                                int curFC = fcCache.get(srcIp).get(tcpSeq);
                                fakeLat.putIfAbsent(curFC, new ArrayList<Long>());
                                fakeLat.get(curFC).add(curLat);
                                if (fakeLat.get(curFC).size() > MAX_BUF) {
                                    fakeLat.get(curFC).remove(0);
                                }
                                if (appLat.containsKey(curFC)) {
                                    if (appLat.get(curFC).size() > 0) {
                                        long curAppLat = appLat.get(curFC).get(fakeCount);
                                        fakeCount = (fakeCount + 1) % (appLat.get(curFC).size());
                                        log.info("fake latency {} real latency {}", curLat, curAppLat);
                                        if (curLat < curAppLat) {
                                            //long start = date.getTime();
                                            //long start = date.getTime();
                                            //long end = 0;
                                            long delay = curAppLat - curLat;
                                            try {
                                                //Thread.sleep(delay);
                                                Thread.sleep(switchLat + delay);
                                            } catch (InterruptedException e) {
                                                System.out.println("Sleep exception.");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            //log.info("Hui Lin packet from {}.{} to {}.{} at switch {} outport {}",
            //        (srcIp / 256) % 256, srcIp % 256, (dstIp / 256) % 256, dstIp % 256,
            //        dpid, outport);

            packetOut(context, outport);


            /*

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(dstId);
            if (dst == null) {
                flood(context);
                return;
            }

            // Otherwise forward and be done with it.
            setUpConnectivity(context, srcId, dstId);
            forwardPacketToDst(context, dst);
            */
        }
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                                             context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void forwardPacketToDst(PacketContext context, Host dst) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(),
                                                          treatment, context.inPacket().unparsed());
        packetService.emit(packet);
        log.info("sending packet: {}", packet);
    }

    // Install a rule forwarding the packet to the specified port.
    private void setUpConnectivity(PacketContext context, HostId srcId, HostId dstId) {
        TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();

        Key key;
        if (srcId.toString().compareTo(dstId.toString()) < 0) {
            key = Key.of(srcId.toString() + dstId.toString(), appId);
        } else {
            key = Key.of(dstId.toString() + srcId.toString(), appId);
        }

        HostToHostIntent intent = (HostToHostIntent) intentService.getIntent(key);
        // TODO handle the FAILED state
        if (intent != null) {
            if (WITHDRAWN_STATES.contains(intentService.getIntentState(key))) {
                HostToHostIntent hostIntent = HostToHostIntent.builder()
                        .appId(appId)
                        .key(key)
                        .one(srcId)
                        .two(dstId)
                        .selector(selector)
                        .treatment(treatment)
                        .build();

                intentService.submit(hostIntent);
            } else if (intentService.getIntentState(key) == IntentState.FAILED) {

                TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

                TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                        .drop().build();

                ForwardingObjective objective = DefaultForwardingObjective.builder()
                        .withSelector(objectiveSelector)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(intent.priority() - 1)
                        .makeTemporary(DROP_RULE_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();

                flowObjectiveService.forward(context.outPacket().sendThrough(), objective);
            }

        } else if (intent == null) {
            HostToHostIntent hostIntent = HostToHostIntent.builder()
                    .appId(appId)
                    .key(key)
                    .one(srcId)
                    .two(dstId)
                    .selector(selector)
                    .treatment(treatment)
                    .build();

            intentService.submit(hostIntent);
        }

    }

}
