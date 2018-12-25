/*
 * Copyright 2014-2015 Open Networking Laboratory
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
package org.onosproject.fwd;

import com.google.common.collect.ImmutableSet;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.util.Tools;
import org.onlab.packet.IPacket;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.ComponentContext;
import org.onosproject.net.packet.DefaultOutboundPacket;
import static org.onosproject.net.flow.DefaultTrafficTreatment.builder;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.Arrays;
//import java.lang.reflect.Array;

//import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Lists;
//import com.google.common.collect.Sets;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.slf4j.LoggerFactory.getLogger;
import java.nio.ByteBuffer;

/**
 * Sample reactive forwarding application.
 */
@Component(immediate = true)
public class ReactiveForwarding {

    private static final int DEFAULT_TIMEOUT = 60;
    private static final int DEFAULT_PRIORITY = 10;

    private static final int DEFAULT_DNP3_PORT = 20000;
    public static final int UPDATE_INTERVAL = 4;
    //public static boolean BEGIN = false;
    //public static int ATTACK_TYPE = 0;
    //private static HashMap<Integer, Integer> visit_dev;
    private int NDEVICE = 0;
    private String storeFile = null;
    

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService cfgService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    private ApplicationId appId;

    //// Hui Lin
    //private List<Integer> accip = null;
    //private List<Integer> inaccip = null;
    //private Map<Integer, PortNumber> ip2port2 = null;
    //private List<Double> realdata = null;
    //private List<Double> decoydata = null;

    private Map<String, Map<String, PortNumber>> mac2port;
    /*
    mac2port dpid1
                mac port
             dpid2
                mac port
     */
    private Map<String, Map<Integer, PortNumber>> ip2port;
    //private Map<Integer, Integer> host2ip;
    private Map<Integer, Integer> ip2host;
    //private Map<String, Integer> switchCount;
    //private String curSwitch;
    //List<String> switches;
    //private Integer COUNT_T = 5;
    //private Random generator;
    //private Map<Integer, List<Double>> replayValues;
    //private Integer REPLAY_MAX = 20;

    @Property(name = "packetOutOnly", boolValue = false,
            label = "Enable packet-out only forwarding; default is false")
    private boolean packetOutOnly = false;

    @Property(name = "packetOutOfppTable", boolValue = false,
            label = "Enable first packet forwarding using OFPP_TABLE port " +
                    "instead of PacketOut with actual port; default is false")
    private boolean packetOutOfppTable = false;

    @Property(name = "flowTimeout", intValue = DEFAULT_TIMEOUT,
            label = "Configure Flow Timeout for installed flow rules; " +
                    "default is 10 sec")
    private int flowTimeout = DEFAULT_TIMEOUT;

    @Property(name = "flowPriority", intValue = DEFAULT_PRIORITY,
            label = "Configure Flow Priority for installed flow rules; " +
                    "default is 10")
    private int flowPriority = DEFAULT_PRIORITY;

    @Property(name = "ipv6Forwarding", boolValue = false,
            label = "Enable IPv6 forwarding; default is false")
    private boolean ipv6Forwarding = false;

    @Property(name = "matchDstMacOnly", boolValue = false,
            label = "Enable matching Dst Mac Only; default is false")
    private boolean matchDstMacOnly = false;

    @Property(name = "matchVlanId", boolValue = false,
            label = "Enable matching Vlan ID; default is false")
    private boolean matchVlanId = false;

    @Property(name = "matchIpv4Address", boolValue = false,
            label = "Enable matching IPv4 Addresses; default is false")
    private boolean matchIpv4Address = false;

    @Property(name = "matchIpv4Dscp", boolValue = false,
            label = "Enable matching IPv4 DSCP and ECN; default is false")
    private boolean matchIpv4Dscp = false;

    @Property(name = "matchIpv6Address", boolValue = false,
            label = "Enable matching IPv6 Addresses; default is false")
    private boolean matchIpv6Address = false;

    @Property(name = "matchIpv6FlowLabel", boolValue = false,
            label = "Enable matching IPv6 FlowLabel; default is false")
    private boolean matchIpv6FlowLabel = false;

    @Property(name = "matchTcpUdpPorts", boolValue = false,
            label = "Enable matching TCP/UDP ports; default is false")
    private boolean matchTcpUdpPorts = false;

    @Property(name = "matchIcmpFields", boolValue = false,
            label = "Enable matching ICMPv4 and ICMPv6 fields; " +
                    "default is false")
    private boolean matchIcmpFields = false;


    @Property(name = "ignoreIPv4Multicast", boolValue = false,
            label = "Ignore (do not forward) IPv4 multicast packets; default is false")
    private boolean ignoreIpv4McastPackets = false;

    private final TopologyListener topologyListener = new InternalTopologyListener();


    @Activate
    public void activate(ComponentContext context) {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("org.onosproject.fwd");

        packetService.addProcessor(processor, PacketProcessor.director(2));
        topologyService.addListener(topologyListener);
        readComponentConfiguration(context);
        requestIntercepts();

        mac2port = Maps.newHashMap();
        ip2host = Maps.newHashMap();
        ip2port = Maps.newHashMap();
        //switchCount = Maps.newHashMap();
        //curSwitch = "hello";
        //switches = null;
        //generator = new Random(0);
        //replayValues = Maps.newHashMap();
        
        Charset charset = Charset.forName("US-ASCII");
        java.nio.file.Path filePath = Paths.get("/home/hugo/Dropbox/Public/ndev.txt");
        try (BufferedReader reader = Files.newBufferedReader(filePath, charset)) {
            String line = null;
            //int row_count = 0;
            //int row_count2 = 0;
            //String deviceName = null;

            int i = 1;
            while ((line = reader.readLine()) != null) {
                //System.out.println(line);
                //
                if (i == 1){
                   storeFile = line; 
                } 
                if (i == 2){
                    NDEVICE = Integer.parseInt(line);
                }
                if (i > 2){
                    throw new IOException("Hui Lin Debug: weird ndev file!");
                }
                i++;
                
            } 
        } catch (IOException x) {
            //System.err.format("IOException: %s%n", x);
            log.warn("Can not open measurement file.");
        }


        ////Hui Lin
        /*
        ip2port2 = Maps.newHashMap();
        ip2port2.putIfAbsent(IPv4.toIPv4Address("10.0.0.1"), PortNumber.portNumber(5));
        ip2port2.putIfAbsent(IPv4.toIPv4Address("10.0.0.2"), PortNumber.portNumber(6));
        ip2port2.putIfAbsent(IPv4.toIPv4Address("10.0.0.3"), PortNumber.portNumber(7));
        ip2port2.putIfAbsent(IPv4.toIPv4Address("10.0.0.4"), PortNumber.portNumber(8));
        ip2port2.putIfAbsent(IPv4.toIPv4Address("10.0.0.5"), PortNumber.portNumber(9));
        */

        /*
        accip = Lists.newArrayList();
        inaccip = Lists.newArrayList();
        accip.add(IPv4.toIPv4Address("10.0.0.1"));
        inaccip.add(IPv4.toIPv4Address("10.0.0.2"));
        inaccip.add(IPv4.toIPv4Address("10.0.0.3"));
        inaccip.add(IPv4.toIPv4Address("10.0.0.4"));
        inaccip.add(IPv4.toIPv4Address(:"10.0.0.5"));
        */

        /*
        realdata = Lists.newArrayList();
        decoydata = Lists.newArrayList();
        realdata.add(46.0);
        realdata.add(54.0);
        realdata.add(65.0);
        realdata.add(15.0);
        realdata.add(30.0);
        decoydata.add(46.0);
        decoydata.add(50.0);
        decoydata.add(9.0);
        decoydata.add(50.0);
        decoydata.add(63.0);
        */

        log.info("Started", appId.id());
    }

    @Deactivate
    public void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        withdrawIntercepts();
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        topologyService.removeListener(topologyListener);
        processor = null;
        mac2port = null;
        ip2host = null;
        ip2port = null;
        //switchCount = null;
        //generator = null;
        //replayValues = null;
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
        requestIntercepts();
    }

    /**
     * Request packet in via packet service.
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV6);
        if (ipv6Forwarding) {
            packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        } else {
            packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        }
    }

    /**
     * Cancel request for packet in via packet service.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * Extracts properties from the component configuration context.
     *
     * @param context the component context
     */
    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();
        boolean packetOutOnlyEnabled =
                isPropertyEnabled(properties, "packetOutOnly");
        if (packetOutOnly != packetOutOnlyEnabled) {
            packetOutOnly = packetOutOnlyEnabled;
            log.info("Configured. Packet-out only forwarding is {}",
                     packetOutOnly ? "enabled" : "disabled");
        }
        boolean packetOutOfppTableEnabled =
                isPropertyEnabled(properties, "packetOutOfppTable");
        if (packetOutOfppTable != packetOutOfppTableEnabled) {
            packetOutOfppTable = packetOutOfppTableEnabled;
            log.info("Configured. Forwarding using OFPP_TABLE port is {}",
                     packetOutOfppTable ? "enabled" : "disabled");
        }
        boolean ipv6ForwardingEnabled =
                isPropertyEnabled(properties, "ipv6Forwarding");
        if (ipv6Forwarding != ipv6ForwardingEnabled) {
            ipv6Forwarding = ipv6ForwardingEnabled;
            log.info("Configured. IPv6 forwarding is {}",
                     ipv6Forwarding ? "enabled" : "disabled");
        }
        boolean matchDstMacOnlyEnabled =
                isPropertyEnabled(properties, "matchDstMacOnly");
        if (matchDstMacOnly != matchDstMacOnlyEnabled) {
            matchDstMacOnly = matchDstMacOnlyEnabled;
            log.info("Configured. Match Dst MAC Only is {}",
                     matchDstMacOnly ? "enabled" : "disabled");
        }
        boolean matchVlanIdEnabled =
                isPropertyEnabled(properties, "matchVlanId");
        if (matchVlanId != matchVlanIdEnabled) {
            matchVlanId = matchVlanIdEnabled;
            log.info("Configured. Matching Vlan ID is {}",
                     matchVlanId ? "enabled" : "disabled");
        }
        boolean matchIpv4AddressEnabled =
                isPropertyEnabled(properties, "matchIpv4Address");
        if (matchIpv4Address != matchIpv4AddressEnabled) {
            matchIpv4Address = matchIpv4AddressEnabled;
            log.info("Configured. Matching IPv4 Addresses is {}",
                     matchIpv4Address ? "enabled" : "disabled");
        }
        boolean matchIpv4DscpEnabled =
                isPropertyEnabled(properties, "matchIpv4Dscp");
        if (matchIpv4Dscp != matchIpv4DscpEnabled) {
            matchIpv4Dscp = matchIpv4DscpEnabled;
            log.info("Configured. Matching IPv4 DSCP and ECN is {}",
                     matchIpv4Dscp ? "enabled" : "disabled");
        }
        boolean matchIpv6AddressEnabled =
                isPropertyEnabled(properties, "matchIpv6Address");
        if (matchIpv6Address != matchIpv6AddressEnabled) {
            matchIpv6Address = matchIpv6AddressEnabled;
            log.info("Configured. Matching IPv6 Addresses is {}",
                     matchIpv6Address ? "enabled" : "disabled");
        }
        boolean matchIpv6FlowLabelEnabled =
                isPropertyEnabled(properties, "matchIpv6FlowLabel");
        if (matchIpv6FlowLabel != matchIpv6FlowLabelEnabled) {
            matchIpv6FlowLabel = matchIpv6FlowLabelEnabled;
            log.info("Configured. Matching IPv6 FlowLabel is {}",
                     matchIpv6FlowLabel ? "enabled" : "disabled");
        }
        boolean matchTcpUdpPortsEnabled =
                isPropertyEnabled(properties, "matchTcpUdpPorts");
        if (matchTcpUdpPorts != matchTcpUdpPortsEnabled) {
            matchTcpUdpPorts = matchTcpUdpPortsEnabled;
            log.info("Configured. Matching TCP/UDP fields is {}",
                     matchTcpUdpPorts ? "enabled" : "disabled");
        }
        boolean matchIcmpFieldsEnabled =
                isPropertyEnabled(properties, "matchIcmpFields");
        if (matchIcmpFields != matchIcmpFieldsEnabled) {
            matchIcmpFields = matchIcmpFieldsEnabled;
            log.info("Configured. Matching ICMP (v4 and v6) fields is {}",
                     matchIcmpFields ? "enabled" : "disabled");
        }
        Integer flowTimeoutConfigured =
                getIntegerProperty(properties, "flowTimeout");
        if (flowTimeoutConfigured == null) {
            flowTimeout = DEFAULT_TIMEOUT;
            log.info("Flow Timeout is not configured, default value is {}",
                     flowTimeout);
        } else {
            flowTimeout = flowTimeoutConfigured;
            log.info("Configured. Flow Timeout is configured to {}",
                     flowTimeout, " seconds");
        }
        Integer flowPriorityConfigured =
                getIntegerProperty(properties, "flowPriority");
        if (flowPriorityConfigured == null) {
            flowPriority = DEFAULT_PRIORITY;
            log.info("Flow Priority is not configured, default value is {}",
                     flowPriority);
        } else {
            flowPriority = flowPriorityConfigured;
            log.info("Configured. Flow Priority is configured to {}",
                     flowPriority);
        }

        boolean ignoreIpv4McastPacketsEnabled =
                isPropertyEnabled(properties, "ignoreIpv4McastPackets");
        if (ignoreIpv4McastPackets != ignoreIpv4McastPacketsEnabled) {
            ignoreIpv4McastPackets = ignoreIpv4McastPacketsEnabled;
            log.info("Configured. Ignore IPv4 multicast packets is {}",
                     ignoreIpv4McastPackets ? "enabled" : "disabled");
        }
    }

    /**
     * Get Integer property from the propertyName
     * Return null if propertyName is not found.
     *
     * @param properties   properties to be looked up
     * @param propertyName the name of the property to look up
     * @return value when the propertyName is defined or return null
     */
    private static Integer getIntegerProperty(Dictionary<?, ?> properties,
                                              String propertyName) {
        Integer value = null;
        try {
            String s = Tools.get(properties, propertyName);
            value = isNullOrEmpty(s) ? value : Integer.parseInt(s);
        } catch (NumberFormatException | ClassCastException e) {
            value = null;
        }
        return value;
    }

    /**
     * Check property name is defined and set to true.
     *
     * @param properties   properties to be looked up
     * @param propertyName the name of the property to look up
     * @return true when the propertyName is defined and set to true
     */
    private static boolean isPropertyEnabled(Dictionary<?, ?> properties,
                                             String propertyName) {
        boolean enabled = false;
        try {
            String flag = Tools.get(properties, propertyName);
            enabled = isNullOrEmpty(flag) ? enabled : flag.equals("true");
        } catch (ClassCastException e) {
            // No propertyName defined.
            enabled = false;
        }
        return enabled;
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.

            //log.info("Hui Lin Handling inbound packet 1");

            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            PortNumber outport;
            IPv4 ipv4Packet;

            HostId srcId = HostId.hostId(ethPkt.getSourceMAC());
            String srcIdStr = srcId.toString();
            HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
            String dstIdStr = dstId.toString();
            DeviceId dpid = pkt.receivedFrom().deviceId();
            String dpidStr = dpid.toString();
            int dpidInt = 0;
            PortNumber inport = pkt.receivedFrom().port();

            Integer srcHostId = 0;
            Integer dstHostId = 0;
            Integer edgeSwitchId = 0;
            //String edgeSwitchIdStr = null;

            if (ethPkt == null) {
                return;
            }


            // Skip IPv6 multicast packet when IPv6 forward is disabled.
            if (!ipv6Forwarding && isIpv6Multicast(ethPkt)) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4){
                //log.info("ip2port {}", ip2port.get(dpidStr));
                //log.info("measurements {}", NetworkManager.global_measure);
                ipv4Packet = (IPv4) ethPkt.getPayload();

            }
            else{
                //context.treatmentBuilder().setOutput(PortNumber.FLOOD);
                //context.send();
                //log.info("non ip packet flood");
                packetOut(context, PortNumber.FLOOD);
                return;
            }

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }

            Integer srcIp = ipv4Packet.getSourceAddress();
            Integer dstIp = ipv4Packet.getDestinationAddress();

            if ( ( (srcIp & 0xFFFF0000) != 0x0A000000 ) || ( (dstIp & 0xFFFF0000) != 0x0A000000 ) ){
                flood(context);
                return;
            }

            srcHostId = srcIp & 0x000000FF;
            dstHostId = dstIp & 0x000000FF;
            if ( srcHostId > NDEVICE ){
                //edgeSwitchId = (srcIp / 256) % 256;
                edgeSwitchId = (srcIp >>> 8) & 0x000000FF;
                dpidInt = Integer.parseInt(dpidStr.substring(15), 16);
                //edgeSwitchIdStr = "of:000000000000000"
            }
            if ( dstHostId > NDEVICE ){
                //edgeSwitchId = (srcIp / 256) % 256;
                edgeSwitchId = (dstIp >>> 8) & 0x000000FF;
                dpidInt = Integer.parseInt(dpidStr.substring(15), 16);
            }


            mac2port.putIfAbsent(dpidStr, Maps.newHashMap());
            ip2port.putIfAbsent(dpidStr, Maps.newHashMap());
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
                    if (srcIp-IPv4.toIPv4Address("10.0.0.1") <= 65535){
                        temp1.putIfAbsent(srcIp, inport);
                        ip2port.get(dpidStr).putIfAbsent(srcIp, inport);
                    }
                }
            }

            //log.info("Hui Lin inbound packet {} from {} to {}", dpid, srcIp, dstIp);
            log.info("Hui Lin packet {} {} from {}.{} to {}.{}", dpid, dpidInt, (srcIp / 256) % 256, srcIp % 256, (dstIp / 256)%256, dstIp % 256);

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

            if ( ((srcHostId > NDEVICE) || (dstHostId > NDEVICE)) && (edgeSwitchId == dpidInt) ){
                log.info("Hui Lin Debug edge switch {}", dpidInt);
                packetOut(context, outport);
            }
            else {
                installRule(context, outport);
            }
            //packetOut(context, outport);

            /*

            HostId id = HostId.hostId(ethPkt.getDestinationMAC());

            // Do not process link-local addresses in any way.
            if (id.mac().isLinkLocal()) {
                return;
            }

            // Do not process IPv4 multicast packets, let mfwd handle them
            if (ignoreIpv4McastPackets && ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (id.mac().isMulticast()) {
                    return;
                }
            }

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(id);
            if (dst == null) {
                flood(context);
                return;
            }

            // Are we on an edge switch that our destination is on? If so,
            // simply forward out to the destination and bail.
            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    installRule(context, dst.location().port());
                    //packetOut(context, dst.location().port());
                }
                return;
            }

            // Otherwise, get a set of paths that lead from here to the
            // destination edge switch.
            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                                             pkt.receivedFrom().deviceId(),
                                             dst.location().deviceId());
            if (paths.isEmpty()) {
                // If there are no paths, flood and bail.
                flood(context);
                return;
            }

            // Otherwise, pick a path that does not lead back to where we
            // came from; if no such path, flood and bail.
            Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
            if (path == null) {
                //log.warn("Don't know where to go from here {} for {} -> {}",
                //         pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                //log.info("Don't know where to go from here {} for {} -> {}", pkt.receivedFrom(),ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context);
                return;
            }

            // Otherwise forward and be done with it.
            installRule(context, path.src().port());
            //packetOut(context, path.src().port());
            */
        }

    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Indicated whether this is an IPv6 multicast packet.
    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }

    // Selects a path from the given set that does not lead back to the
    // specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        Path lastPath = null;
        for (Path path : paths) {
            lastPath = path;
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return lastPath;
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

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber) {
        //
        // We don't support (yet) buffer IDs in the Flow Service so
        // packet out first.
        //
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        // If PacketOutOnly or ARP packet than forward directly to output port
        if (packetOutOnly || inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber);
            return;
        }

        //
        // If matchDstMacOnly
        //    Create flows matching dstMac only
        // Else
        //    Create flows with default matching and include configured fields
        //
        if (matchDstMacOnly) {
            selectorBuilder.matchEthDst(inPkt.getDestinationMAC());
        } else {
            selectorBuilder.matchInPort(context.inPacket().receivedFrom().port())
                    .matchEthSrc(inPkt.getSourceMAC())
                    .matchEthDst(inPkt.getDestinationMAC());

            // If configured Match Vlan ID
            if (matchVlanId && inPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                selectorBuilder.matchVlanId(VlanId.vlanId(inPkt.getVlanID()));
            }

            //
            // If configured and EtherType is IPv4 - Match IPv4 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv4Address && inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
                byte ipv4Protocol = ipv4Packet.getProtocol();
                Ip4Prefix matchIp4SrcPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                          Ip4Prefix.MAX_MASK_LENGTH);
                Ip4Prefix matchIp4DstPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                          Ip4Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPSrc(matchIp4SrcPrefix)
                        .matchIPDst(matchIp4DstPrefix);

                if (matchIpv4Dscp) {
                    byte dscp = ipv4Packet.getDscp();
                    byte ecn = ipv4Packet.getEcn();
                    selectorBuilder.matchIPDscp(dscp).matchIPEcn(ecn);
                }

                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                            .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
                if (matchIcmpFields && ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                    ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchIcmpType(icmpPacket.getIcmpType())
                            .matchIcmpCode(icmpPacket.getIcmpCode());
                }
            }

            //
            // If configured and EtherType is IPv6 - Match IPv6 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv6Address && inPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Packet = (IPv6) inPkt.getPayload();
                byte ipv6NextHeader = ipv6Packet.getNextHeader();
                Ip6Prefix matchIp6SrcPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getSourceAddress(),
                                          Ip6Prefix.MAX_MASK_LENGTH);
                Ip6Prefix matchIp6DstPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getDestinationAddress(),
                                          Ip6Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV6)
                        .matchIPv6Src(matchIp6SrcPrefix)
                        .matchIPv6Dst(matchIp6DstPrefix);

                if (matchIpv6FlowLabel) {
                    selectorBuilder.matchIPv6FlowLabel(ipv6Packet.getFlowLabel());
                }

                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                            .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
                if (matchIcmpFields && ipv6NextHeader == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchIcmpv6Type(icmp6Packet.getIcmpType())
                            .matchIcmpv6Code(icmp6Packet.getIcmpCode());
                }
            }
        }
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .add();

        //log.info("Hui Lin: not installed rule heres ");
        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                                     forwardingObjective);

        //
        // If packetOutOfppTable
        //  Send packet back to the OpenFlow pipeline to match installed flow
        // Else
        //  Send packet direction on the appropriate port
        //
        if (packetOutOfppTable) {
            packetOut(context, PortNumber.TABLE);
        } else {
            packetOut(context, portNumber);
        }
    }

    private class InternalTopologyListener implements TopologyListener {
        @Override
        public void event(TopologyEvent event) {
            List<Event> reasons = event.reasons();
            if (reasons != null) {
                reasons.forEach(re -> {
                    if (re instanceof LinkEvent) {
                        LinkEvent le = (LinkEvent) re;
                        if (le.type() == LinkEvent.Type.LINK_REMOVED) {
                            fixBlackhole(le.subject().src());
                        }
                    }
                });
            }
        }
    }

    private void fixBlackhole(ConnectPoint egress) {
        Set<FlowEntry> rules = getFlowRulesFrom(egress);
        Set<SrcDstPair> pairs = findSrcDstPairs(rules);

        Map<DeviceId, Set<Path>> srcPaths = new HashMap<>();

        for (SrcDstPair sd : pairs) {
            // get the edge deviceID for the src host
            Host srcHost = hostService.getHost(HostId.hostId(sd.src));
            Host dstHost = hostService.getHost(HostId.hostId(sd.dst));
            if (srcHost != null && dstHost != null) {
                DeviceId srcId = srcHost.location().deviceId();
                DeviceId dstId = dstHost.location().deviceId();
                log.trace("SRC ID is " + srcId + ", DST ID is " + dstId);

                cleanFlowRules(sd, egress.deviceId());

                Set<Path> shortestPaths = srcPaths.get(srcId);
                if (shortestPaths == null) {
                    shortestPaths = topologyService.getPaths(topologyService.currentTopology(),
                            egress.deviceId(), srcId);
                    srcPaths.put(srcId, shortestPaths);
                }
                backTrackBadNodes(shortestPaths, dstId, sd);
            }
        }
    }

    // Backtracks from link down event to remove flows that lead to blackhole
    private void backTrackBadNodes(Set<Path> shortestPaths, DeviceId dstId, SrcDstPair sd) {
        for (Path p : shortestPaths) {
            List<Link> pathLinks = p.links();
            for (int i = 0; i < pathLinks.size(); i = i + 1) {
                Link curLink = pathLinks.get(i);
                DeviceId curDevice = curLink.src().deviceId();

                // skipping the first link because this link's src has already been pruned beforehand
                if (i != 0) {
                    cleanFlowRules(sd, curDevice);
                }

                Set<Path> pathsFromCurDevice =
                        topologyService.getPaths(topologyService.currentTopology(),
                                                 curDevice, dstId);
                if (pickForwardPathIfPossible(pathsFromCurDevice, curLink.src().port()) != null) {
                    break;
                } else {
                    if (i + 1 == pathLinks.size()) {
                        cleanFlowRules(sd, curLink.dst().deviceId());
                    }
                }
            }
        }
    }

    // Removes flow rules off specified device with specific SrcDstPair
    private void cleanFlowRules(SrcDstPair pair, DeviceId id) {
        log.trace("Searching for flow rules to remove from: " + id);
        log.trace("Removing flows w/ SRC=" + pair.src + ", DST=" + pair.dst);
        for (FlowEntry r : flowRuleService.getFlowEntries(id)) {
            boolean matchesSrc = false, matchesDst = false;
            for (Instruction i : r.treatment().allInstructions()) {
                if (i.type() == Instruction.Type.OUTPUT) {
                    // if the flow has matching src and dst
                    for (Criterion cr : r.selector().criteria()) {
                        if (cr.type() == Criterion.Type.ETH_DST) {
                            if (((EthCriterion) cr).mac().equals(pair.dst)) {
                                matchesDst = true;
                            }
                        } else if (cr.type() == Criterion.Type.ETH_SRC) {
                            if (((EthCriterion) cr).mac().equals(pair.src)) {
                                matchesSrc = true;
                            }
                        }
                    }
                }
            }
            if (matchesDst && matchesSrc) {
                log.trace("Removed flow rule from device: " + id);
                flowRuleService.removeFlowRules((FlowRule) r);
            }
        }

    }

    // Returns a set of src/dst MAC pairs extracted from the specified set of flow entries
    private Set<SrcDstPair> findSrcDstPairs(Set<FlowEntry> rules) {
        ImmutableSet.Builder<SrcDstPair> builder = ImmutableSet.builder();
        for (FlowEntry r : rules) {
            MacAddress src = null, dst = null;
            for (Criterion cr : r.selector().criteria()) {
                if (cr.type() == Criterion.Type.ETH_DST) {
                    dst = ((EthCriterion) cr).mac();
                } else if (cr.type() == Criterion.Type.ETH_SRC) {
                    src = ((EthCriterion) cr).mac();
                }
            }
            builder.add(new SrcDstPair(src, dst));
        }
        return builder.build();
    }

    // Returns set of flow entries which were created by this application and
    // which egress from the specified connection port
    private Set<FlowEntry> getFlowRulesFrom(ConnectPoint egress) {
        ImmutableSet.Builder<FlowEntry> builder = ImmutableSet.builder();
        flowRuleService.getFlowEntries(egress.deviceId()).forEach(r -> {
            if (r.appId() == appId.id()) {
                r.treatment().allInstructions().forEach(i -> {
                    if (i.type() == Instruction.Type.OUTPUT) {
                        if (((Instructions.OutputInstruction) i).port().equals(egress.port())) {
                            builder.add(r);
                        }
                    }
                });
            }
        });

        return builder.build();
    }

    // Wrapper class for a source and destination pair of MAC addresses
    private final class SrcDstPair {
        final MacAddress src;
        final MacAddress dst;

        private SrcDstPair(MacAddress src, MacAddress dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            SrcDstPair that = (SrcDstPair) o;
            return Objects.equals(src, that.src) &&
                    Objects.equals(dst, that.dst);
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }
    }

    private int computecrc(byte[] dataOctet) {

        //precompute crc tables
        int[] crctable = new int[256];
        int crc;
        for (int i = 0; i < 256; i++) {
            crc = i;
            for (int j = 0; j < 8; j++) {
                if ((crc & 0x0001) != 0) {
                    crc = (crc >> 1) ^ 0xA6BC;
                    //Generating polynomial.
                } else {
                    crc = crc >> 1;
                }
            }
            crctable[i] = (crc);
        }

        //calculate crc
        crc = 0x0000;
        int index;
        for (int i = 0; i < dataOctet.length; i++) {
            index = (crc ^ dataOctet[i]) & 0x00FF;
            crc = crctable[index] ^ (crc >> 8);
        }

        return ~crc & 0xFFFF;
    }

    /*
    * Datalinke layer
    * 05 64 | len | Ctrl |  dst_lsb dst_msb |  src_lsb src_msb | crc |
      *
    * */
    private void DNP3Out(PacketContext context, byte[] dnp3, PortNumber port, List<Double> decoy) {

        DeviceId original = context.outPacket().sendThrough();

        //// modify the payload
        byte[] magic = {(byte) 0x05, (byte) 0x64};
        byte len = 0;
        byte ctrl = dnp3[3];
        byte[] dest = {dnp3[4], dnp3[5]};
        byte[] src = {dnp3[6], dnp3[7]};
        byte[] crc1 = {dnp3[8], dnp3[9]};
        byte app_ctrl = dnp3[11];
        byte fc = dnp3[12];
        byte[] iid = {dnp3[13], dnp3[14]};

        byte[] obj1 = {dnp3[15], dnp3[16]};

        //log.info("obj group {}", obj1[0]);

        if (obj1[0] == 0x1e) {
            //// modify the payload of read response only
            byte quaf = dnp3[17];
            int number_obj = 8;
            byte starti = 0;
            byte stopi = (byte)(number_obj-1);
            int obj_size = number_obj * 5;
            byte[] obj_buffer = new byte[obj_size];
            for (int i = 0; i < number_obj; i++){
                obj_buffer[i * 5] = 0x02;
                for (int j = 0; j < 4; j++) {
                    if (i < decoy.size()) {
                        int temp = new Double((decoy.get(i) * 1)).intValue();
                        obj_buffer[i*5 + j + 1] = (byte)((temp >> (j*8)) & 0x000000FF);
                    } else {
                        obj_buffer[i*5 + j + 1] = 0x00;
                    }
                }
            }
            int dpu_size = 1 + 4 + 2 + 1 + 1 + 1 + obj_size;
            //// transport, app header, object type field, qua field, start and stop index
            byte[] dnp3_dpu = new byte[dpu_size]; /// include transport and application layer data no crc
            byte[] dnp3_header = new byte[DNP3.DNP3_HEADER_LENGTH];
            System.arraycopy(dnp3, 0, dnp3_header, 0, DNP3.DNP3_HEADER_LENGTH);
            //ByteBuffer dnp3_header_buf = ByteBuffer.wrap(Arrays.copyOfRange(dnp3, 0, 10));
            ByteBuffer dnp3_dpu_buf = ByteBuffer.wrap(dnp3_dpu);
            dnp3_dpu_buf.put(Arrays.copyOfRange(dnp3, 10, 18));
            dnp3_dpu_buf.put(starti);
            dnp3_dpu_buf.put(stopi);
            dnp3_dpu_buf.put(obj_buffer);
            int crc = 0;
            byte crc_low = 0;
            byte crc_high = 0;

            dnp3_header[2] = (byte)(dpu_size + 5);
            //dnp3_header_buf.put(2, (byte)(dpu_size + 5));
            //byte [] dnp3_header =  new byte[dnp3_header_buf.remaining()];
            //dnp3_header_buf.get(dnp3_header, 0, dnp3_header.length);
            crc = computecrc(Arrays.copyOfRange(dnp3_header, 0, 8));
            //log.info(Integer.toHexString(dnp3B[8]) + Integer.toHexString(dnp3B[9]));
            //byte crc_low = (byte)(crc & 0x00FF);
            //byte crc_high = (byte)((crc >> 8) & 0x00FF);
            dnp3_header[8] = crc_low;
            dnp3_header[9] = crc_high;
            //// adding crc
            int dnp3_payload_size = new Double(Math.ceil(dpu_size/16.0 - 0.001)).intValue() * 2 + dpu_size;
            byte[] dnp3_payload = new byte[dnp3_payload_size];
            ByteBuffer dnp3_payload_buf = ByteBuffer.wrap(dnp3_payload);
            byte [] data_block = new byte[16];
            for( int i = 0; i < dpu_size ; i = i + 16) {
                //log.info("Hui Lin: {} {}", i, dnp3_dpu_buf.remaining());
                if ((i + 16) <= dpu_size) {
                    //dnp3_dpu_buf.get(data_block, i, 16);
                    data_block = Arrays.copyOfRange(dnp3_dpu, i, i+16);
                } else {
                    //dnp3_dpu_buf.get(data_block, i, dpu_size - i);
                    data_block = Arrays.copyOfRange(dnp3_dpu, i, dpu_size);
                }
                crc = computecrc(data_block);
                crc_low = (byte)(crc & 0x00FF);
                crc_high = (byte)((crc >> 8) & 0x00FF);
                dnp3_payload_buf.put(data_block);
                dnp3_payload_buf.put(crc_low);
                dnp3_payload_buf.put(crc_high);
            }
            //int dnp3out_size = 10 + dnp3_payload_size;
            //byte[] dnp3out = new byte[dnp3out_size];
            //ByteBuffer dnp3out_buf = ByteBuffer.wrap(dnp3out);
            //dnp3out_buf.put(dnp3_header_buf);
            //dnp3out_buf.put(dnp3_payload_buf);
            //DefaultOutboundPacket spoofPayload = new DefaultOutboundPacket()
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            Ethernet ethPktOut = new Ethernet();
            ethPktOut.setDestinationMACAddress(ethPkt.getDestinationMACAddress());
            ethPktOut.setSourceMACAddress(ethPkt.getSourceMACAddress());
            ethPktOut.setEtherType(ethPkt.getEtherType());

            IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
            IPv4 ipv4PacketOut = new IPv4();
            ipv4PacketOut.setDestinationAddress(ipv4Packet.getDestinationAddress());
            ipv4PacketOut.setSourceAddress(ipv4Packet.getSourceAddress());
            ipv4PacketOut.setTtl(ipv4Packet.getTtl());
            ipv4PacketOut.setIdentification(ipv4Packet.getIdentification());
            ipv4PacketOut.setProtocol(ipv4Packet.getProtocol());
            ipv4PacketOut.setFlags(ipv4Packet.getFlags());
            ipv4PacketOut.setChecksum((short)0);


            TCP tcpPacket = (TCP) ipv4Packet.getPayload();
            //log.info("Hui Lin original {}", tcpPacket.getPayload().serialize());
            //log.info("Hui Lin original {}", ethPkt.serialize());
            TCP tcpPacketOut = new TCP();
            tcpPacketOut.setSourcePort(tcpPacket.getSourcePort());
            tcpPacketOut.setDestinationPort(tcpPacket.getDestinationPort());
            tcpPacketOut.setSequence(tcpPacket.getSequence());
            tcpPacketOut.setAcknowledge(tcpPacket.getAcknowledge());
            tcpPacketOut.setWindowSize(tcpPacket.getWindowSize());
            tcpPacketOut.setFlags(tcpPacket.getFlags());
            tcpPacketOut.setDataOffset(tcpPacket.getDataOffset());
            tcpPacketOut.setOptions(tcpPacket.getOptions());
            tcpPacketOut.setFlags(tcpPacket.getFlags());
            tcpPacketOut.setChecksum((short) 0);


            IPacket dnp3P = tcpPacket.getPayload();
            byte[] dnp3B = dnp3P.serialize();

            DNP3 dnp3out = new DNP3(dnp3_header, dnp3_payload);
            //IPacket dnp3out = tcpPacket.getPayload();
            tcpPacketOut.setPayload(dnp3out);
            ipv4PacketOut.setPayload(tcpPacketOut);
            ethPktOut.setPayload(ipv4PacketOut);

            //DNP3 dnp3out = new DNP3(Arrays.copyOfRange(dnp3B, 0, 10), Arrays.copyOfRange(dnp3B, 10, dnp3B.length));
            //tcpPacket.setPayload(dnp3out);
            //ipv4Packet.setPayload(tcpPacket);
            //ethPkt.setPayload(ipv4Packet);

            DefaultOutboundPacket outPacket = new DefaultOutboundPacket(original,
                    builder().setOutput(port).build(),
                    ByteBuffer.wrap(ethPktOut.serialize()));
            //ByteBuffer.wrap(ethPkt.serialize()));
            //tcpPacket.setPayload()

            dnp3P = tcpPacketOut.getPayload();
            //dnp3P = tcpPacket.getPayload();
            dnp3B = dnp3P.serialize();
            //log.info("Hui Lin send decoy {}", dnp3B);
            //OutboundPacket out2 = outPacket;
            if (outPacket == null) {
                log.warn("Setting outbound packet onot correctly");
            }
            //log.info("send decoy {} {}", original, port.toString());
            //log.info("{}", outPacket.sendThrough());
            byte[] b = new byte[outPacket.data().remaining()];
            outPacket.data().get(b);
            //log.info("{}", b);
            packetService.emit(outPacket);
        } else {
            log.warn("not support dnp3 obj at this moment");
        }


        //DefaultOutboundPacket spoofPayload = new DefaultOutboundPacket()
    }
}
