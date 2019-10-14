/*
 * Copyright 2018-present Open Networking Foundation
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
package org.onosproject.test.action;

import com.google.common.collect.ImmutableList;
import jdk.nashorn.internal.ir.annotations.Immutable;
import org.apache.felix.scr.annotations.*;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.GroupId;
import org.onosproject.floodlightpof.protocol.OFMatch20;
import org.onosproject.floodlightpof.protocol.OFPort;
import org.onosproject.floodlightpof.protocol.action.OFAction;
import org.onosproject.floodlightpof.protocol.table.OFFlowTable;
import org.onosproject.floodlightpof.protocol.table.OFTableType;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceAdminService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.DefaultPofActions;
import org.onosproject.net.flow.instructions.DefaultPofInstructions;
import org.onosproject.net.group.*;
import org.onosproject.net.table.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowTableStore flowTableStore;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceAdminService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowTableStore tableStore;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowTableService flowTableService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected GroupService groupService;

    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;

    int port1 = 1;
    int port2 = 2;
    int port3 = 3;
    int controller_port = (int) PortNumber.CONTROLLER.toLong();


    /* deviceId List */
    private DeviceId sw1 = DeviceId.deviceId("pof:0000000000000001");
    private DeviceId sw2 = DeviceId.deviceId("pof:0000000000000002");
    private DeviceId sw3 = DeviceId.deviceId("pof:0000000000000003");
    private DeviceId sw4 = DeviceId.deviceId("pof:0000000000000004");
    private DeviceId sw5 = DeviceId.deviceId("pof:0000000000000005");
    private DeviceId sw6 = DeviceId.deviceId("pof:0000000000000006");

    /* global tableId. */
    private byte sw1_tbl0, sw1_tbl1;
    private byte sw2_tbl0, sw2_tbl1;
    private byte sw3_tbl0, sw3_tbl1;
    private byte sw4_tbl0, sw4_tbl1;
    private byte sw5_tbl0, sw5_tbl1;
    private byte sw6_tbl0, sw6_tbl1;

    /* tableId */
    private byte global_tbl_0 = 0;

    /* group table key */
    private String sel_key = "abc";
    private int sel_groupId = 0x16;
    private String all_key = "def";
    private int all_groupId = 0x17;
    private String sw2_sel_key = "abcd";
    private String sw2_sel_key2 = "bcde";
    private int sw2_sel_groupId = 0x18;
    private String sw2_all_key = "defg";
    private int sw2_all_groupId = 0x19;


    /* match field values */
    private String srcIp = "0a000001";
    private String int_type = "0908";


    // field_id
    public final short DMAC = 1;
    public final short SMAC = 2;
    public final short TTL = 9;
    public final short SIP = 12;
    public final short DIP = 13;
    public final short TEST = 14;  // added protocol field, {272, 16, '0908'}
    public final short INT_TYPE = 15;  // added protocol field, {272, 16, '0908'}
    public final short INT_TTL = 16;   // {288, 8}

    // macro definition
    static final short ETH_HEADER_LEN         =     14 * 8;
    static final short IPV4_HEADER_LEN        =     20 * 8;
    static final short INT_HEADER_BASE        =     34 * 8;
    static final short INT_HEADER_LEN         =      4 * 8;
    static final short INT_HEADER_TYPE_OFF    =     34 * 8;
    static final short INT_HEADER_TYPE_LEN    =      2 * 8;
    static final short INT_HEADER_TTL_OFF     =     36 * 8;
    static final short INT_HEADER_TTL_LEN     =      1 * 8;
    static final short INT_HEADER_MAPINFO_OFF =     37 * 8;
    static final short INT_HEADER_MAPINFO_LEN =      1 * 8;
    static final short INT_HEADER_DATA_OFF    =    38 * 8;
    static final short INT_DATA_DPID_END_OFF  =    42 * 8;    // 38 + 4 = 42

    /* tsf: INT data len. */
    static final short INT_DATA_DPID_LEN         =    4 * 8;
    static final short INT_DATA_IN_PORT_LEN      =    1 * 8;
    static final short INT_DATA_OUT_PORT_LEN     =    1 * 8;
    static final short INT_DATA_INGRESS_TIME_LEN =    8 * 8;
    static final short INT_DATA_HOP_LATENCY_LEN  =    2 * 8;
    static final short INT_DATA_BANDWIDTH_LEN    =    4 * 8;

    /* tsf: sleep how long. */
    final static long TIME_INTERVAL = 8000;    // in ms, scenario1: 8000ms, scenario2: 100ms

    /* test path revalidation flag. */
    private boolean TEST_PATH_RAVALIDATION = false;     // used at sw2
    private boolean TEST_PATH_FUNCTION = false;         // used by all sw.
    /* these two flag cannot be both true. */
    private boolean SIMULATE_SEL_GROUP_TABLE = false;   // used at sw2
    private boolean SIMULATE_ALL_GROUP_TABLE = !SIMULATE_SEL_GROUP_TABLE;  // used at sw3
    /* to adjust the sampling rate at INT source node. */
    private boolean P4_sINT = false;                         // used at sw1 for P4-sINT
    private boolean P4_ECMP = true;            // used at sw2 for P4-sINT
    private boolean SEL_INT = true;                          // used at sw1 for Sel-INT

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.onosproject.test.action");
        /* test INT collector performance, single node. all_group add_int_field to collector and user.  */
//        pofTestStart1();

        /* test performance: no INT, per-packet INT, selective INT, single node */
//        pofTestStart2();

        /* test selective INT precision or path revalidation, six node topology */
//        pofTestStart3();

        /* compare sel-INT and p4-sINT, six node topology, for fig.15(a) */
        pofTestStart4();
    }

    @Deactivate
    protected void deactivate() {
//        pofTestStop1();
//        pofTestStop2();
//        pofTestStop3();
        pofTestStop4();
    }

    /**
     * ==================== pof test ==================
     */
    public void pofTestStart1() {
        log.info("org.onosproject.pof.test.action Started");

        /** SRC(sw1): send flow table match ip{208, 32} */
        sw1_tbl0 = send_pof_flow_table_match_SIP_at_SRC(sw1, "AddIntHeader");

        // adjust add_int_field's value[0], i.e. 'mapInfo'
        install_pof_all_group_rule_match_srcIP(sw1, sw6_tbl0, srcIp, all_key, all_groupId, 12, port2, port3, "3f");
        install_pof_group_rule_match_srcIp(sw1, sw1_tbl0, srcIp, all_groupId, 12);
    }

    public void pofTestStop1() {
        log.info("org.onosproject.pof.test.action Stopped");
        remove_pof_group_tables(sw1, all_key);
        remove_pof_flow_table(sw1, sw1_tbl0);
    }

    public void pofTestStart2() {
        log.info("org.onosproject.pof.test.action Started");

        /** SRC(sw1): send flow table match ip{208, 32} */
        sw1_tbl0 = send_pof_flow_table_match_SIP_at_SRC(sw1, "AddIntHeader");

        /* test: no INT */
//        install_pof_no_int_output_flow_rule(sw1, sw1_tbl0, srcIp, port2, 12);

        /* test: per-packet INT */
        install_pof_add_int_field_rule_match_srcIp(sw1, sw1_tbl0, srcIp, port1, 12, "3f");

        /* test: selective INT, adjust w1:w2 in first method. (w1 > w2), w2 runs INT */
        short w1 = 1, w2 = 9;
        int ports = port1;
        String mapInfo = "07";
//        install_pof_select_group_rule(sw1, sw1_tbl0, ports, ports, srcIp, sel_key, sel_groupId, 12, w1, w2, mapInfo);
//        install_pof_group_rule_match_srcIp(sw1, sw1_tbl0, srcIp, sel_groupId, 12);
    }

    public void pofTestStop2() {
        log.info("org.onosproject.pof.test.action Stopped");
        remove_pof_group_tables(sw1, sel_key);

        remove_pof_flow_table(sw1, sw1_tbl0);
    }

    public void pofTestStart3() {
        log.info("org.onosproject.pof.test.action Started");

        sw1_tbl0 = send_pof_flow_table_match_SIP_at_SRC(sw1, "AddIntHeader");
        sw2_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw2, "AddIntMetadata");
        sw3_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw3, "AddIntMetadata");

        if (TEST_PATH_RAVALIDATION) {
            sw4_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw4, "AddIntMetadata");
        }

        sw5_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw5, "AddIntMetadata");
        sw6_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw6, "MirrorIntMetadata");

        // wait 1s
        try {
            Thread.sleep(1500);
        } catch (Exception e) {
            e.printStackTrace();
        }

        /** SRC(sw1): send flow table match ip{208, 32} */
//        sw1_tbl0 = send_pof_flow_table_match_SIP_at_SRC(sw1, "AddIntHeader");
        /* rule1: send select group to add INT header. w1: output; w2: add_int_header.*/
        short weight1 = 24, weight2 = 1;
        String mapInfo = "01";
        install_pof_select_group_rule(sw1, sw1_tbl0, port3, port3, srcIp, sel_key, sel_groupId, 12, weight1, weight2, mapInfo);
        install_pof_group_rule_match_srcIp(sw1, sw1_tbl0, srcIp, sel_groupId, 12);
        try {
            Thread.sleep(500);
        } catch (Exception e) {
            e.printStackTrace();
        }
        /* rule2: default rule, mask is 0x00000000 */
        install_pof_output_flow_rule_match_default_ip_at_SRC(sw1, sw1_tbl0, srcIp, port3, 2);

        /** INTER(sw2): send flow table match int_type{272, 16} */
//        sw2_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw2, "AddIntMetadata");
        if (!TEST_PATH_RAVALIDATION) {  // normal
            /* rule1: add_int_action. if revalidate path, with add_func_field action */
            install_pof_add_int_field_rule_match_type(sw2, sw2_tbl0, int_type, port2, 12, "ff");   // "ff" means read mapInfo from pkts
            /* rule2: default rule, mask is 0x0000 */
            install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw2, sw2_tbl0, int_type, port2, 1);
        } else { // assume that we mis-config group table here, so that we get two out_port to revalidate path. cannot be true both!

            /* we will execute one more add_func_field as key. the pkt's 'mapInfo' should be 0x01 (deviceId).
             * @format: type + ttl + sw1 + sw1_key + sw2 + sw2_key + ...
             * */

            log.info("test path revalidation. ");
            if (SIMULATE_SEL_GROUP_TABLE) {   /* simulate select group table */
                /* rule1: send select group to add INT header. w21: output; w22: add_int_header. */
                short weight21 = 5, weight22 = 5;
                install_pof_select_group_rule_at_sw2(sw2, sw2_tbl0, port2, port3, int_type, sw2_sel_key, sw2_sel_groupId, 12, weight21, weight22, "ff");
                install_pof_group_rule_match_type(sw2, sw2_tbl0, int_type, sw2_sel_groupId, 12);
                try {
                    Thread.sleep(500);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                /* rule2: default rule, mask is 0x0000 */
                install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw2, sw2_tbl0, int_type, port2, 1);
            }

            if (SIMULATE_ALL_GROUP_TABLE) { /* simulate all group table */
                /* rule1: mirror INT packets to collector and usr */
                install_pof_all_group_rule_match_type_at_sw2(sw2, sw2_tbl0, int_type, sw2_all_key, sw2_all_groupId, 1, port2, port3, "ff"); // "ff" means read mapInfo from pkts
                install_pof_group_rule_match_type(sw2, sw2_tbl0, int_type, sw2_all_groupId, 12);
                try {
                    Thread.sleep(500);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                /* rule2: default rule, mask is 0x0000*/
//                install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw6, sw6_tbl0, int_type, port2, 1);  // usr_port
            }
        }

        /** INTER(sw3): send flow table match int_type{272, 16} */
//        sw3_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw3, "AddIntMetadata");
        /* rule1: add_int_action. if revalidate path, with add_func_field action */
        install_pof_add_int_field_rule_match_type(sw3, sw3_tbl0, int_type, port2, 12, "ff");   // "ff" means read mapInfo from pkts
        /* rule2: default rule, mask is 0x0000 */
        install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw3, sw2_tbl0, int_type, port2, 1);

        /* if we need revalidate path, then we should send flow rule to sw4. */
        if (TEST_PATH_RAVALIDATION) {
            /** INTER(sw4): send flow table match int_type{272, 16} */
//        sw4_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw4, "AddIntMetadata");
            /* rule1: add_int_action. if revalidate path, with add_func_field action */
            install_pof_add_int_field_rule_match_type(sw4, sw4_tbl0, int_type, port2, 12, "ff");   // "ff" means read mapInfo from pkts
            /* rule2: default rule, mask is 0x0000 */
            install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw4, sw4_tbl0, int_type, port2, 1);
        }

        /** INTER(sw5): send flow table match int_type{272, 16} */
//        sw5_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw5, "AddIntMetadata");
        /* rule1: add_int_action. if revalidate path, with add_func_field action */
        install_pof_add_int_field_rule_match_type(sw5, sw5_tbl0, int_type, port3, 12, "ff");   // "ff" means read mapInfo from pkts
        /* rule2: default rule, mask is 0x0000 */
        install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw5, sw5_tbl0, int_type, port3, 1);

        /** SINK(sw6): send flow table match int_type{272, 16} */
//        sw6_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw6, "MirrorIntMetadata");
        /* rule1: mirror INT packets to collector and usr */
        install_pof_all_group_rule_match_type(sw6, sw6_tbl0, int_type, all_key, all_groupId, 12, port2, port3, "ff"); // "ff" means read mapInfo from pkts
        install_pof_group_rule_match_type(sw6, sw2_tbl0, int_type, all_groupId, 12);
        try {
            Thread.sleep(500);
        } catch (Exception e) {
            e.printStackTrace();
        }
        /* rule2: default rule, mask is 0x0000*/
        install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw6, sw6_tbl0, int_type, port2, 1);  // usr_port

        /** SINK(sw6): trick, we don't mirror for performance consideration. */
//        install_pof_add_int_field_rule_match_type(sw6, sw6_tbl0, int_type, port3, 12, "ff");   // "ff" means read mapInfo from pkts

        /* simulate the intentional attack. */
        boolean SIMULATE_ATTACK = false;
        if (SIMULATE_ATTACK) {
            String old_key, new_key;
            String[] sel_group_keys = {"abc", "bcde"};
            String[] mapInfo_array = {"03", "01"};   // we make 0x03 run 5s, 0x01 runs 25s, 30s as a big period
            for (int i = 0; i < 8; ) {
                if (i % 2 == 0) {
                    try {
                        Thread.sleep(25000);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    try {
                        Thread.sleep(5000);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                if (i == 3) {   // at i=3, we change output port (port2->port3) at sw2
                    install_mod_pof_select_group_rule_at_sw2(sw2, sw2_tbl0, port3, port3, int_type, sw2_sel_key, sw2_sel_key2, sw2_sel_groupId, 12, weight1, weight2, "ff");
                }

                mapInfo = mapInfo_array[i % 2];
                old_key = sel_group_keys[i % 2];
                new_key = sel_group_keys[++i % 2];
                log.info("i:{}, mapInfo: {}, old_key: {}, new_key: {}", i, mapInfo, old_key, new_key);

                /* change group table at sw1 */
                install_mod_pof_select_group_rule(sw1, sw1_tbl0, port3, port3, srcIp, old_key, new_key, sel_groupId, 12, weight1, weight2, mapInfo);
            }
        }

    }

    public void pofTestStop3() {
        /* remove group tables */
        remove_pof_group_tables(sw1, sel_key);
        remove_pof_group_tables(sw6, all_key);

        /* for path revalidation scenario only. */
        if (SIMULATE_SEL_GROUP_TABLE) {
            remove_pof_group_tables(sw2, sw2_sel_key);
            remove_pof_group_tables(sw2, sw2_sel_key2);
        }
        if (SIMULATE_ALL_GROUP_TABLE) {
            remove_pof_group_tables(sw2, sw2_all_key);
        }

        /* remove flow tables */
        remove_pof_flow_table(sw1, sw1_tbl0);
        remove_pof_flow_table(sw2, sw2_tbl0);
        remove_pof_flow_table(sw3, sw3_tbl0);

        if (TEST_PATH_RAVALIDATION) {
            remove_pof_flow_table(sw4, sw4_tbl0);
        }

        remove_pof_flow_table(sw5, sw5_tbl0);
        remove_pof_flow_table(sw6, sw6_tbl0);
        log.info("org.onosproject.test.action Stopped");
    }

    public void pofTestStart4() {
        log.info("org.onosproject.pof.test.action Started");

        sw1_tbl0 = send_pof_flow_table_match_SIP_at_SRC(sw1, "AddIntHeader");
        sw2_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw2, "AddIntMetadata");
        sw3_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw3, "AddIntMetadata");

        if (TEST_PATH_RAVALIDATION) {
            sw4_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw4, "AddIntMetadata");
        }

        sw5_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw5, "AddIntMetadata");
        sw6_tbl0 = send_pof_flow_table_match_INT_TYPE_at_INTER(sw6, "MirrorIntMetadata");

        // wait 1s
        try {
            Thread.sleep(1000);
        } catch (Exception e) {
            e.printStackTrace();
        }

        /** SRC(sw1): send flow table match ip{208, 32} */
        String mapInfo = "01";
        int sampling_rate_N = 25;           // for p4-sINT
        short weight1 = 49, weight2 = 1;    // for Sel-INT, w2: add_int_header
        if (P4_sINT) {
            /* rule1: send add_int_field rule to insert INT header in 1/N, the key->len refers to 'N'.*/
            install_pof_add_int_field_rule_match_srcIp(sw1, sw1_tbl0, srcIp, port3, 12, mapInfo, sampling_rate_N);
        }
        if (SEL_INT) {
            /* rule1: send select group to add INT header. w1: output; w2: add_int_header.*/
            install_pof_select_group_rule(sw1, sw1_tbl0, port3, port3, srcIp, sel_key, sel_groupId, 12, weight1, weight2, mapInfo);
            install_pof_group_rule_match_srcIp(sw1, sw1_tbl0, srcIp, sel_groupId, 12);
        }
        /* rule2: default rule, mask is 0x00000000 */
//        install_pof_output_flow_rule_match_default_ip_at_SRC(sw1, sw1_tbl0, srcIp, port3, 1);

        /** INTER(sw2): send flow table match int_type{272, 16} */
        if (!TEST_PATH_RAVALIDATION) {  // normal
            /* rule1: add_int_action. if revalidate path, with add_func_field action */
            install_pof_add_int_field_rule_match_type(sw2, sw2_tbl0, int_type, port2, 12, "ff");   // "ff" means read mapInfo from pkts
            /* rule2: default rule, mask is 0x0000 */
            install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw2, sw2_tbl0, int_type, port2, 1);
        } else { // assume that we mis-config group table here, so that we get two out_port to revalidate path. cannot be true both!

            log.info("test path revalidation.");
            if (SIMULATE_SEL_GROUP_TABLE) {   /* simulate select group table */
                /* rule1: send select group to add INT header. w21: output; w22: add_int_header. */
                short weight21 = 5, weight22 = 5;
                install_pof_select_group_rule_at_sw2(sw2, sw2_tbl0, port2, port3, int_type, sw2_sel_key, sw2_sel_groupId, 12, weight21, weight22, "ff");
                install_pof_group_rule_match_type(sw2, sw2_tbl0, int_type, sw2_sel_groupId, 12);
                /* rule2: default rule, mask is 0x0000 */
                install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw2, sw2_tbl0, int_type, port2, 1);
            }
        }

        /** INTER(sw3): send flow table match int_type{272, 16} */
        /* rule1: add_int_action. if revalidate path, with add_func_field action */
        install_pof_add_int_field_rule_match_type(sw3, sw3_tbl0, int_type, port2, 12, "ff");   // "ff" means read mapInfo from pkts
        /* rule2: default rule, mask is 0x0000 */
        install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw3, sw2_tbl0, int_type, port2, 1);

        /* if we need revalidate path, then we should send flow rule to sw4. */
        if (TEST_PATH_RAVALIDATION) {
            /** INTER(sw4): send flow table match int_type{272, 16} */
            /* rule1: add_int_action. if revalidate path, with add_func_field action */
            install_pof_add_int_field_rule_match_type(sw4, sw4_tbl0, int_type, port2, 12, "ff");   // "ff" means read mapInfo from pkts
            /* rule2: default rule, mask is 0x0000 */
            install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw4, sw4_tbl0, int_type, port2, 1);
        }

        /** INTER(sw5): send flow table match int_type{272, 16} */
        /* rule1: add_int_action. if revalidate path, with add_func_field action */
        install_pof_add_int_field_rule_match_type(sw5, sw5_tbl0, int_type, port3, 12, "ff");   // "ff" means read mapInfo from pkts
        /* rule2: default rule, mask is 0x0000 */
        install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw5, sw5_tbl0, int_type, port3, 1);

        /** SINK(sw6): send flow table match int_type{272, 16} */
        /* rule1: mirror INT packets to collector and usr */
        install_pof_all_group_rule_match_type(sw6, sw6_tbl0, int_type, all_key, all_groupId, 12, port2, port3, "ff"); // "ff" means read mapInfo from pkts
        install_pof_group_rule_match_type(sw6, sw2_tbl0, int_type, all_groupId, 12);
        /* rule2: default rule, mask is 0x0000*/
        install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(sw6, sw6_tbl0, int_type, port2, 1);  // usr_port

        /** SINK(sw6): trick, we don't mirror for performance consideration. */
//        install_pof_add_int_field_rule_match_type(sw6, sw6_tbl0, int_type, port3, 12, "ff");   // "ff" means read mapInfo from pkts

        // =========================================================================================

        /** Evaluate to change sampling rate for p4-sINT at sw1.
         *  The trace is [50, 100, 50, 100, 50, 100, ...] Mpps, and sampling rate will be double for [1/50, 1/25, 1/12, 1/6, 1/3, 1].
         * */
        if (P4_sINT) {  // sampling_rate_N: 50 -> 25 -> 12 -> 6 -> 3 -> 1
            int i=0;
            log.info("P4-sINT, sampling_rate_N: {}, i:{}th", sampling_rate_N, i++);
           /* try {
                Thread.sleep(80000);
            } catch (Exception e) {
                e.printStackTrace();
            }  // for alignment*/
            // wait
            try {
                Thread.sleep(TIME_INTERVAL);
            } catch (Exception e) {
                e.printStackTrace();
            }

            sampling_rate_N = 25;
            install_pof_add_int_field_rule_match_srcIp(sw1, sw1_tbl0, srcIp, port3, 12, mapInfo, sampling_rate_N);
            log.info("P4-sINT, sampling_rate_N: {}, i:{}th", sampling_rate_N, i++);
            // wait
            try {
                Thread.sleep(TIME_INTERVAL);
            } catch (Exception e) {
                e.printStackTrace();
            }

            sampling_rate_N = 12;
            install_pof_add_int_field_rule_match_srcIp(sw1, sw1_tbl0, srcIp, port3, 12, mapInfo, sampling_rate_N);
            log.info("P4-sINT, sampling_rate_N: {}, i:{}th", sampling_rate_N, i++);
            // wait
            try {
                Thread.sleep(TIME_INTERVAL);
            } catch (Exception e) {
                e.printStackTrace();
            }

            sampling_rate_N = 6;
            install_pof_add_int_field_rule_match_srcIp(sw1, sw1_tbl0, srcIp, port3, 12, mapInfo, sampling_rate_N);
            log.info("P4-sINT, sampling_rate_N: {}, i:{}th", sampling_rate_N, i++);
            // wait
            try {
                Thread.sleep(TIME_INTERVAL);
            } catch (Exception e) {
                e.printStackTrace();
            }

            sampling_rate_N = 3;
            install_pof_add_int_field_rule_match_srcIp(sw1, sw1_tbl0, srcIp, port3, 12, mapInfo, sampling_rate_N);
            log.info("P4-sINT, sampling_rate_N: {}, i:{}th", sampling_rate_N, i++);
            try {
                Thread.sleep(TIME_INTERVAL);
            } catch (Exception e) {
                e.printStackTrace();
            }

            sampling_rate_N = 1;
            install_pof_add_int_field_rule_match_srcIp(sw1, sw1_tbl0, srcIp, port3, 12, mapInfo, sampling_rate_N);
            log.info("P4-sINT, sampling_rate_N: {}, i:{}th", sampling_rate_N, i);
        }

        /** Evaluate to change sampling rate for P4-sINT at sw1 per 100ms when ECMP (sw_id changes)
         *  The trace is stable at 100 Mpps, and sampling rate will be [1/50, 1/25, 1/12, 1/6, 1/3, 1].
         * */
        if (P4_ECMP) {

        }

        /**
         * Evaluate to change sampling rate for Sel-INT at sw1.
         * The trace is [50, 100, 50, 100, 50, 100, ...] Mpps, and sampling rate will be [1/50, 1/25, 1/50, 1/25, ...].
         */
        if (SEL_INT) {
            String old_key, new_key;
            String[] sel_group_keys = {"abc", "bcde"};
            short[][] weights = {{49, 1}, {24, 1}};  // w1:w2, w2=add_int_header
            /*try {
                Thread.sleep(8000);
            } catch (Exception e) {
                e.printStackTrace();
            }*/
            for (int i=0; i<30; ) {
                // mod group table at sw1
                try {
                    Thread.sleep(TIME_INTERVAL);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                old_key = sel_group_keys[i % 2];
                new_key = sel_group_keys[++i % 2];
                weight1 = weights[i % 2][0];
                weight2 = weights[i % 2][1];
                log.info("i:{}, mapInfo:{}, old_key:{}, new_key:{}, w1:{}, w2:{}", i, mapInfo, old_key, new_key, weight1, weight2);

                /* change group table at sw1 */
                install_mod_pof_select_group_rule(sw1, sw1_tbl0, port3, port3, srcIp, old_key, new_key, sel_groupId, 12, weight1, weight2, mapInfo);
            }
        }
    }

    public void pofTestStop4() {
        /* remove group tables */
        if (SEL_INT) {
            remove_pof_group_tables(sw1, sel_key);
            remove_pof_group_tables(sw1, "bcde");
        }
        remove_pof_group_tables(sw6, all_key);

        /* for path revalidation scenario only. */
        if (SIMULATE_SEL_GROUP_TABLE) {
            remove_pof_group_tables(sw2, sw2_sel_key);
            remove_pof_group_tables(sw2, sw2_sel_key2);
        }
        if (SIMULATE_ALL_GROUP_TABLE) {
            remove_pof_group_tables(sw2, sw2_all_key);
        }

        /* remove flow tables */
        remove_pof_flow_table(sw1, sw1_tbl0);
        remove_pof_flow_table(sw2, sw2_tbl0);
        remove_pof_flow_table(sw3, sw3_tbl0);

        if (TEST_PATH_RAVALIDATION) {
            remove_pof_flow_table(sw4, sw4_tbl0);
        }

        remove_pof_flow_table(sw5, sw5_tbl0);
        remove_pof_flow_table(sw6, sw6_tbl0);
        log.info("org.onosproject.test.action Stopped: all flow/group tables are removed!");
    }

    public byte send_pof_flow_table_match_SIP_at_SRC(DeviceId deviceId, String table_name) {
        byte globeTableId = (byte) tableStore.getNewGlobalFlowTableId(deviceId, OFTableType.OF_MM_TABLE);
        byte tableId = tableStore.parseToSmallTableId(deviceId, globeTableId);
//        byte tableId = global_tbl_0;

        OFMatch20 srcIP = new OFMatch20();
        srcIP.setFieldId((short) SIP);
        srcIP.setFieldName("srcIP");
        srcIP.setOffset((short) 208);
        srcIP.setLength((short) 32);

        ArrayList<OFMatch20> match20List = new ArrayList<>();
        match20List.add(srcIP);

        OFFlowTable ofFlowTable = new OFFlowTable();
        ofFlowTable.setTableId(tableId);
        ofFlowTable.setTableName(table_name);
        ofFlowTable.setMatchFieldList(match20List);
        ofFlowTable.setMatchFieldNum((byte) 1);
        ofFlowTable.setTableSize(4);
        ofFlowTable.setTableType(OFTableType.OF_MM_TABLE);
        ofFlowTable.setCommand(null);
        ofFlowTable.setKeyLength((short) 32);

        FlowTable.Builder flowTable = DefaultFlowTable.builder()
                .withFlowTable(ofFlowTable)
                .forTable(tableId)
                .forDevice(deviceId)
                .fromApp(appId);

        flowTableService.applyFlowTables(flowTable.build());

        log.info("table<{}> applied to device<{}> successfully.", tableId, deviceId.toString());

        return tableId;
    }

    public byte send_pof_flow_table_match_INT_TYPE_at_INTER(DeviceId deviceId, String table_name) {
        byte globeTableId = (byte) tableStore.getNewGlobalFlowTableId(deviceId, OFTableType.OF_MM_TABLE);
        byte tableId = tableStore.parseToSmallTableId(deviceId, globeTableId);

//        byte tableId = global_tbl_0;

        OFMatch20 int_type = new OFMatch20();
        int_type.setFieldId(INT_TYPE);
        int_type.setFieldName("int_type");
        int_type.setOffset(INT_HEADER_BASE);
        int_type.setLength(INT_HEADER_TYPE_LEN);

        ArrayList<OFMatch20> match20List = new ArrayList<>();
        match20List.add(int_type);

        OFFlowTable ofFlowTable = new OFFlowTable();
        ofFlowTable.setTableId(tableId);
        ofFlowTable.setTableName(table_name);
        ofFlowTable.setMatchFieldList(match20List);
        ofFlowTable.setMatchFieldNum((byte) 1);
        ofFlowTable.setTableSize(32);
        ofFlowTable.setTableType(OFTableType.OF_MM_TABLE);
        ofFlowTable.setCommand(null);
        ofFlowTable.setKeyLength(INT_HEADER_TYPE_LEN);

        FlowTable.Builder flowTable = DefaultFlowTable.builder()
                .withFlowTable(ofFlowTable)
                .forTable(tableId)
                .forDevice(deviceId)
                .fromApp(appId);

        flowTableService.applyFlowTables(flowTable.build());
        log.info("table<{}> applied to device<{}> successfully.", tableId, deviceId.toString());

        return tableId;
    }

    public void remove_pof_flow_table(DeviceId deviceId, byte tableId) {
        flowRuleService.removeFlowRulesById(appId);  // for ovs-pof
        flowTableService.removeFlowTablesByTableId(deviceId, FlowTableId.valueOf(tableId));
        log.info(" remove table from device<{}>  table<{}> successfully.", deviceId.toString(), tableId);
    }

    public void install_pof_output_flow_rule_match_default_ip_at_SRC(DeviceId deviceId, byte tableId, String srcIP, int outport,
                                                           int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "00000000"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());
        log.info("match_default_ip_at_SRC: apply to deviceId<{}> tableId<{}>, entryId=<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }

    public void install_pof_output_flow_rule_match_default_type_at_INTER_or_SINK(DeviceId deviceId, byte tableId, String intType, int outport,
                                                                     int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(INT_TYPE, INT_HEADER_BASE, INT_HEADER_TYPE_LEN, intType, "0000"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());
        log.info("match_default_type_at_INTER_or_SINK: apply to deviceId<{}> tableId<{}>, entryId=<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }

    /**
     * test no INT scenarios. only output packets.
     * @actions output
     * @param deviceId such as "pof:000000000000000x"
     * @param tableId shoule be table0
     * @param srcIP such as "0a000001", hex str
     * @param outport output port
     * @param priority 12
     */
    public void install_pof_no_int_output_flow_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength((short) SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_output: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());
        log.info("Test no INT: apply to deviceId<{}> tableId<{}>, entryId=<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }

    /**
     * test per INT scenarios. add INT metadata into packets per packet. adjust metadata type with 'mapInfo'
     * @actions add_int_field + output
     * @param deviceId such as "pof:000000000000000x"
     * @param tableId shoule be table0
     * @param int_type such as "0908", hex str
     * @param outport output port
     * @param priority 12
     * @param mapInfo hex str, one byte. such as '3f'
     */
    public void install_pof_add_int_field_rule_match_type(DeviceId deviceId, byte tableId, String int_type, int outport, int priority, String mapInfo) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(INT_TYPE, INT_HEADER_BASE, INT_HEADER_TYPE_LEN, int_type, "ffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short int_field_id = -1;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();

        /* 0b'00 00 00 00 = x | x | bandwidth | egress_time || ingress_time | out_port | in_port | dpid.
         * if 'mapInfo' == 0xff, then read 'mapInfo' from packets.
         * at src node or single node, 'mapInfo' cannot be 0xff.
         */
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, INT_HEADER_TYPE_LEN, mapInfo).action();
        OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action();

        // modify INT-ttl
        OFMatch20 Field_INT_ttl =  new OFMatch20();
        Field_INT_ttl.setFieldName("INT_ttl");
        Field_INT_ttl.setFieldId(INT_TTL);
        Field_INT_ttl.setOffset(INT_HEADER_TTL_OFF);
        Field_INT_ttl.setLength(INT_HEADER_TTL_LEN);
        OFAction action_inc_INT_ttl = DefaultPofActions.modifyField(Field_INT_ttl, 1).action();

        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();

        actions.add(action_add_int_field);    /* add int metadata. */
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            actions.add(action_add_func_field);  /* This action used to revalidate path. */
        }
        actions.add(action_inc_INT_ttl);      /* increment int_ttl field by 1 */
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_add_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("install_pof_int_field_flow_rule_match_type: apply to deviceId<{}> tableId<{}> entryId<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }

    public void install_modify_pof_add_int_field_rule_match_type(DeviceId deviceId, byte tableId, String int_type, long entryId, int outport, int priority, String mapInfo) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(INT_TYPE, INT_HEADER_BASE, INT_HEADER_TYPE_LEN, int_type, "ffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short int_field_id = -1;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();

        /* 0b'00 00 00 00 = x | x | bandwidth | egress_time || ingress_time | out_port | in_port | dpid.
         * if 'mapInfo' == 0xff, then read 'mapInfo' from packets.
         * at src node or single node, 'mapInfo' cannot be 0xff.
         */
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, INT_HEADER_TYPE_LEN, mapInfo).action();
        OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action();

        // modify INT-ttl
        OFMatch20 Field_INT_ttl =  new OFMatch20();
        Field_INT_ttl.setFieldName("INT_ttl");
        Field_INT_ttl.setFieldId(INT_TTL);
        Field_INT_ttl.setOffset(INT_HEADER_TTL_OFF);
        Field_INT_ttl.setLength(INT_HEADER_TTL_LEN);
        OFAction action_inc_INT_ttl = DefaultPofActions.modifyField(Field_INT_ttl, 1).action();

        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();

        actions.add(action_add_int_field);    /* add int metadata. */
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            actions.add(action_add_func_field);  /* This action used to revalidate path. */
        }
        actions.add(action_inc_INT_ttl);      /* increment int_ttl field by 1 */
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_add_field: {}.", actions);

        // apply
//        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        long newFlowEntryId = entryId;
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("install_pof_int_field_flow_rule_match_type: apply to deviceId<{}> tableId<{}> entryId<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }

    /**
     * test per INT scenarios. add INT metadata into packets per packet. adjust metadata type with 'mapInfo'
     * @actions add_int_field + output
     * @param deviceId such as "pof:000000000000000x"
     * @param tableId shoule be table0
     * @param srcIp such as "0a000001", hex str
     * @param outport output port
     * @param priority 12
     * @param mapInfo hex str, one byte. such as '3f'
     */
    public void install_pof_add_int_field_rule_match_srcIp(DeviceId deviceId, byte tableId, String srcIp, int outport, int priority, String mapInfo) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIp, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short int_field_id = -1;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();

        /* 0b'00 00 00 00 = x | x | bandwidth | egress_time || ingress_time | out_port | in_port | dpid.
         * if 'mapInfo' == 0xff, then read 'mapInfo' from packets.
         * at src node or single node, 'mapInfo' cannot be 0xff.
         */
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, INT_HEADER_TYPE_LEN, mapInfo).action();
        OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action();

        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();

        actions.add(action_add_int_field);
//        actions.add(action_add_func_field);  /* This action used to revalidate path. */
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_add_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("install_pof_int_field_flow_rule_match_srcIP: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }


    /**
     * 1/N sampling method to insert INT header. just apply 'add_int_field' action
     * @param sampling_rate_N
     */
    public void install_pof_add_int_field_rule_match_srcIp(DeviceId deviceId, byte tableId, String srcIp, int outport,
                                                           int priority, String mapInfo, int sampling_rate_N) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIp, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short int_field_id = -1;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();

        /* 0b'00 00 00 00 = x | x | bandwidth | egress_time || ingress_time | out_port | in_port | dpid.
         * if 'mapInfo' == 0xff, then read 'mapInfo' from packets.
         * at src node or single node, 'mapInfo' cannot be 0xff.
         * sampling_rate_N define the 'N' to select one in N
         */
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, sampling_rate_N * 8, mapInfo).action();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        actions.add(action_add_int_field);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));

        // get existed flow rules in flow table. if the srcIp equals, then delete it
        /*Map<Integer, FlowRule> existedFlowRules = new HashMap<>();
        existedFlowRules = flowTableStore.getFlowEntries(deviceId, FlowTableId.valueOf(tableId));
        if(existedFlowRules != null) {
            for(Integer flowEntryId : existedFlowRules.keySet()) {
                if(existedFlowRules.get(flowEntryId).selector().equals(trafficSelector.build())) {
                    flowTableService.removeFlowEntryByEntryId(deviceId, tableId, flowEntryId);
                    log.info("install_pof_add_int_field_rule_match_srcIp: remove flow entry, deviceId<{}> tableId<{}> entryId<{}>",
                            deviceId.toString(), tableId, flowEntryId);
                }
            }
        }*/

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("install_pof_int_field_flow_rule_match_srcIP: apply to deviceId<{}> tableId<{}> entryId<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }

    /**
     * test selective INT scenarios. adjust the selective ratio with 'weight1':'weight2', adjust metadata type with 'mapInfo'
     * @actions bucket1: output, weight1
     *          bucket2: add_int_field + output, weight2
     * @param deviceId such as "pof:000000000000000x"
     * @param tableId shoule be table0
     * @param srcIp such as "0a000001", hex str
     * @param weight1 the weight of bucket1
     * @param weight2 the weight of bucket2
     * @param mapInfo hex str, one byte. such as '3f'
     */
    public void install_pof_add_selective_field_rule(DeviceId deviceId, byte tableId, String srcIp, short weight1, short weight2, String mapInfo) {
        install_pof_selective_int_group_rule(deviceId, tableId, srcIp, "abc", 0x16, 1, true, "def",
                weight1, weight2, mapInfo);
//        install_pof_select_group_rule(deviceId, tableId, "0a000001", "abc", 0x16, 1, true, "def");
        install_pof_group_rule_match_srcIp(deviceId, tableId, srcIp, 0x16, 1);
    }

    /**
     * selective group table
     * @param deviceId
     * @param tableId
     * @param srcIP
     * @param old_key_str
     * @param groupId
     * @param priority
     * @param is_add
     * @param new_key_str
     * @param weight1
     * @param weight2
     * @param mapInfo
     */
    public void install_pof_selective_int_group_rule(DeviceId deviceId, byte tableId, String srcIP,String old_key_str, int groupId,
                                              int priority, boolean is_add, String new_key_str, short weight1, short weight2, String mapInfo) {
        GroupId select_group_id = new GroupId(groupId);

        byte[] keyData = old_key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);

        // out_port
        int port1 = 1;
        int port2 = 2;
        int port3 = 3;
        int controller_port = (int) PortNumber.CONTROLLER.toLong();
        int port = port2;

        // bucket1: action: output
        TrafficTreatment.Builder trafficTreatment_bucket1 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket1 = new ArrayList<>();
        OFAction action_output1 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, port3).action();
        actions_bucket1.add(action_output1);
        trafficTreatment_bucket1.add(DefaultPofInstructions.applyActions(actions_bucket1));

        // bucket1: weight
        GroupBucket bucket1 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket1.build(), (short) 9);

        // bucket2: action: add_int_field + output
        short int_field_id = -1;
        TrafficTreatment.Builder trafficTreatment_bucket2 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket2 = new ArrayList<>();
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, (short) 16, mapInfo).action();
        OFAction action_output2 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, port3).action();
        actions_bucket2.add(action_add_int_field);
        actions_bucket2.add(action_output2);
        trafficTreatment_bucket2.add(DefaultPofInstructions.applyActions(actions_bucket2));

        // bucket2: weight
        GroupBucket bucket2 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket2.build(), (short) 1);

        // buckets
        GroupBuckets select_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription select_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.SELECT, select_group_buckets, key, select_group_id.id(), appId);

        if (is_add) {  // add group
            log.info("Add group table");
            groupService.addGroup(select_group);
        } else {      // mod group
            log.info("Mod group table");
            byte[] new_keyData = new_key_str.getBytes();
            final GroupKey new_key = new DefaultGroupKey(new_keyData);
            GroupBuckets new_buckets = new GroupBuckets(ImmutableList.of(bucket2));
            groupService.setBucketsForGroup(deviceId, key, new_buckets, new_key, appId);
        }
    }

    // if outport=CONTROLLER, then it will packet_in to controller
    public void install_pof_output_flow_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength((short) SIP, (short) 208, (short) 32, srcIP, "ffffffff"));

//        matchList.add(Criteria.matchOffsetLength((short) SMAC, (short) 48, (short) 48, srcIP, "ffffffffffff"));

//        matchList.add(Criteria.matchOffsetLength((short) SIP, (short) 208, (short) 32, srcIP, "00000000"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
//        OFAction action_add_field1 = DefaultPofActions.addField((short) 16, (short) 272, (short) 64, "0102030405060708").action();
        OFAction action_add_dynamic_field1 = DefaultPofActions.addField((short) -1, (short) 272, (short) 16, "3f").action();
//        actions.add(action_add_field1);
//        actions.add(action_add_dynamic_field1);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_output: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                                                   .forDevice(deviceId)
                                                   .forTable(tableId)
                                                   .withSelector(trafficSelector.build())
                                                   .withTreatment(trafficTreamt.build())
                                                   .withPriority(priority)
                                                   .withCookie(newFlowEntryId)
                                                   .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("installOutputFlowRule: apply to deviceId<{}> tableId<{}>, entryId=<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }

    public void install_pof_set_field_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
//        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        matchList.add(Criteria.matchOffsetLength((short) SMAC, (short) 48, (short) 48, srcIP, "ffffffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_set_dstIp = DefaultPofActions.setField(DIP, (short) 240, (short) 32, "0a020202", "ffffffff").action();
        OFAction action_set_srcIp = DefaultPofActions.setField(SIP, (short) 208, (short) 32, "0a0a0a0a", "ffffffff").action();
//        OFAction action_set_ttl = DefaultPofActions.setField(TTL, (short) 176, (short) 8, "66", "ff").action();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
//        actions.add(action_set_dstIp);
        actions.add(action_set_srcIp);
//        actions.add(action_set_ttl);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_set_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("installSetFieldFlowRule: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }

    public void install_pof_add_static_field_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
//        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "00000000"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short field_id1 = 17;
        short field_id2 = 18;
        short field_id3 = 19;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_add_field1 = DefaultPofActions.addField(field_id1, (short) 272, (short) 16, "0908").action();
//        OFAction action_add_field2 = DefaultPofActions.addField(field_id2, (short) 272, (short) 16, "1918").action();
//        OFAction action_add_field3 = DefaultPofActions.addField(field_id3, (short) 272, (short) 16, "2928").action();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        actions.add(action_add_field1);
//        actions.add(action_add_field2);
//        actions.add(action_add_field3);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_add_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("installAddFieldFlowRule: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }


    public void install_pof_add_dynamic_field_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short field_id1 = -1;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();

        /* 0b'00 00 00 00 = x | x | bandwidth | egress_time || ingress_time | out_port | in_port | dpid.
        * if 'filed_value' == 0xff, then read 'mapInfo' from packets.
        */
        OFAction action_add_field1 = DefaultPofActions.addField(field_id1, INT_HEADER_DATA_OFF, (short) 16, "01").action();
        OFAction action_add_func_field1 = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action();

        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();

        actions.add(action_add_field1);
//        actions.add(action_add_func_field1);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_add_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("install_pof_dynamic_field_flow_rule: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }

    public void install_pof_delete_field_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short field_id1 = 17;
        short offset = 272;
        int len = 16;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_delete_field = DefaultPofActions.deleteField(offset, len).action();
//        OFAction action_delete_field1 = DefaultPofActions.deleteField((short) 272, (short) 16).action();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        actions.add(action_delete_field);
//        actions.add(action_delete_field1);
//        actions.add(action_delete_field1);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_delete_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("installDeleteFieldFlowRule: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }

    /* if 'offset' = -1, then truncate packets into 'len' length from pkt_header. */
    public void install_pof_delete_trunc_field_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short offset = -1;
        int len = 8 * 8;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_delete_field = DefaultPofActions.deleteField(offset, len).action();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        actions.add(action_delete_field);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_delete_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("installDeleteFieldFlowRule: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }

    /* if 'len' = -1, then delete INT data according to its 'mapInfo', 'offset' defines the start location of INT_header */
    public void install_pof_delete_int_field_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        short offset = 34 * 8;
        int len = -1;
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_delete_field = DefaultPofActions.deleteField(offset, len).action();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        actions.add(action_delete_field);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_delete_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("installDeleteFieldFlowRule: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }


    public void install_pof_modify_field_rule(DeviceId deviceId, byte tableId, String srcIP, int outport, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // modify ttl
        OFMatch20 FIELD_TTL = new OFMatch20();
        FIELD_TTL.setFieldName("TTL");
        FIELD_TTL.setFieldId(TTL);
        FIELD_TTL.setOffset((short) 176);
        FIELD_TTL.setLength((short) 8);

        // modify srcIp's last byte
        OFMatch20 FIELD_SIP = new OFMatch20();
        FIELD_SIP.setFieldName("SIP");
        FIELD_SIP.setFieldId(SIP);
        FIELD_SIP.setOffset((short) (208 + 24));
        FIELD_SIP.setLength((short) 8);

        // modify dstIp's last byte
        OFMatch20 FIELD_DIP = new OFMatch20();
        FIELD_DIP.setFieldName("DIP");
        FIELD_DIP.setFieldId(DIP);
        FIELD_DIP.setOffset((short) (240 + 24));
        FIELD_DIP.setLength((short) 8);

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_modify_ttl = DefaultPofActions.modifyField(FIELD_TTL, 65535).action();
//        OFAction action_modify_dip = DefaultPofActions.modifyField(FIELD_DIP, 12).action();
//        OFAction action_modify_sip = DefaultPofActions.modifyField(FIELD_SIP, 12).action();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport).action();
        OFAction action_add_field1 = DefaultPofActions.addField((short) 16, (short) 272, (short) 64, "0102030405060708").action();
        actions.add(action_add_field1);
        actions.add(action_modify_ttl);
//        actions.add(action_modify_dip);
//        actions.add(action_modify_sip);
        actions.add(action_output);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_modify_field: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("installModifyFieldFlowRule: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }

    public void installDropFlowRule(DeviceId deviceId, byte tableId, String srcIP, int outport) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_drop = DefaultPofActions.drop(1).action();
        actions.add(action_drop);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));
        log.info("action_drop: {}.", actions);

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(1)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());

        log.info("installDropFlowRule: apply to deviceId<{}> tableId<{}>", deviceId.toString(), tableId);
    }

    public void install_pof_group_rule_match_srcIp(DeviceId deviceId, byte tableId, String srcIP, int groupId, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_group = DefaultPofActions.group(groupId).action();
        actions.add(action_group);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());
        log.info("group_rule_match_srcIp: apply to deviceId<{}> tableId<{}> entryId<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }


    public void install_pof_group_rule_match_type(DeviceId deviceId, byte tableId, String int_type, int groupId, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(INT_TYPE, INT_HEADER_BASE, INT_HEADER_TYPE_LEN, int_type, "ffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action
        TrafficTreatment.Builder trafficTreamt = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_group = DefaultPofActions.group(groupId).action();
        actions.add(action_group);
        trafficTreamt.add(DefaultPofInstructions.applyActions(actions));

        // apply
        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreamt.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());
        log.info("group_rule_match_type: apply to deviceId<{}> tableId<{}> entryId<{}>", deviceId.toString(), tableId, newFlowEntryId);
    }

    /* sel_group at sw1 (src_node), bucket2 do INT operation. */
    public void install_pof_select_group_rule(DeviceId deviceId, byte tableId, int out_port1, int out_port2, String srcIP,
                                              String key_str, int groupId, int priority,
                                              short weight1, short weight2, String mapInfo) {
        GroupId select_group_id = new GroupId(groupId);

        byte[] keyData = key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);

        /* modify SIP: make this flow into 2 flows. otherwise, match error at next node. Only used at src.
         *             because dpdk->rss_hash will hash src_ip and dst_ip and see them as one flow. We insert
         *             INT_HEADER behind IPv4.dst, will mis-match (encounter match-only-one-flow again)
         *             at next node.
         */
        short int_field_id = -1;
        OFMatch20 Field_SIP =  new OFMatch20();
        Field_SIP.setFieldName("SIP_B3");
        Field_SIP.setFieldId(SIP);
        Field_SIP.setOffset((short) (208 + 16));
        Field_SIP.setLength((short) 8);
        OFAction action_inc_SIP = DefaultPofActions.modifyField(Field_SIP, 1).action();

        // modify INT-ttl
        OFMatch20 Field_INT_ttl =  new OFMatch20();
        Field_INT_ttl.setFieldName("INT_ttl");
        Field_INT_ttl.setFieldId(INT_TTL);
        Field_INT_ttl.setOffset(INT_HEADER_TTL_OFF);
        Field_INT_ttl.setLength(INT_HEADER_TTL_LEN);
        OFAction action_inc_INT_ttl = DefaultPofActions.modifyField(Field_INT_ttl, 1).action();

        // bucket1: action = output
        TrafficTreatment.Builder trafficTreatment_bucket1 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket1 = new ArrayList<>();
        OFAction action_output1 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, out_port1).action();
        actions_bucket1.add(action_inc_SIP);   // must contain this action, make 'rss_hash' different
        actions_bucket1.add(action_output1);
        trafficTreatment_bucket1.add(DefaultPofInstructions.applyActions(actions_bucket1));

        // bucket1: weight1 -- output
        GroupBucket bucket1 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket1.build(), weight1);


        // bucket2: action = add_int_field + output, inc_int_ttl at data plane (src node).
        TrafficTreatment.Builder trafficTreatment_bucket2 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket2 = new ArrayList<>();
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_BASE, (short) 24, mapInfo).action();
        OFAction action_output2 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, out_port2).action();
        actions_bucket2.add(action_add_int_field);
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action(); // for path revalidation
            actions_bucket2.add(action_add_func_field);
        }
//        actions_bucket2.add(action_inc_INT_ttl);   // no need inc_INT_ttl here, we directly set it at src node.
        actions_bucket2.add(action_output2);
        trafficTreatment_bucket2.add(DefaultPofInstructions.applyActions(actions_bucket2));

        // bucket2: weight2 -- int-operation
        GroupBucket bucket2 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket2.build(), weight2);

        // buckets
        GroupBuckets select_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription select_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.SELECT, select_group_buckets, key, select_group_id.id(), appId);

        groupService.addGroup(select_group);
        log.info("Add select group table to deviceId<{}>, groupId<{}>, w1:w2={}:{}", deviceId.toString(), groupId, weight1, weight2);
    }

    /* moddify sel_group Mod at sw1 (src_node), bucket2 do INT operation. */
    public void install_mod_pof_select_group_rule(DeviceId deviceId, byte tableId, int out_port1, int out_port2, String srcIP,
                                              String old_key_str, String new_key_str, int groupId, int priority,
                                              short weight1, short weight2, String mapInfo) {
        GroupId select_group_id = new GroupId(groupId);

        byte[] keyData = old_key_str.getBytes();
        final GroupKey old_key = new DefaultGroupKey(keyData);

        /* modify SIP: make this flow into 2 flows. otherwise, match error at next node. Only used at src.
         *             because dpdk->rss_hash will hash src_ip and dst_ip and see them as one flow. We insert
         *             INT_HEADER behind IPv4.dst, will mis-match (encounter match-only-one-flow again)
         *             at next node.
         */
        short int_field_id = -1;
        OFMatch20 Field_SIP =  new OFMatch20();
        Field_SIP.setFieldName("SIP_B3");
        Field_SIP.setFieldId(SIP);
        Field_SIP.setOffset((short) (208 + 16));
        Field_SIP.setLength((short) 8);
        OFAction action_inc_SIP = DefaultPofActions.modifyField(Field_SIP, 1).action();

        // modify INT-ttl
        OFMatch20 Field_INT_ttl =  new OFMatch20();
        Field_INT_ttl.setFieldName("INT_ttl");
        Field_INT_ttl.setFieldId(INT_TTL);
        Field_INT_ttl.setOffset(INT_HEADER_TTL_OFF);
        Field_INT_ttl.setLength(INT_HEADER_TTL_LEN);
        OFAction action_inc_INT_ttl = DefaultPofActions.modifyField(Field_INT_ttl, 1).action();

        // bucket1: action = output
        TrafficTreatment.Builder trafficTreatment_bucket1 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket1 = new ArrayList<>();
        OFAction action_output1 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, out_port1).action();
        actions_bucket1.add(action_inc_SIP);   // must contain this action, make 'rss_hash' different
        actions_bucket1.add(action_output1);
        trafficTreatment_bucket1.add(DefaultPofInstructions.applyActions(actions_bucket1));

        // bucket1: weight1 -- output
        GroupBucket bucket1 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket1.build(), weight1);


        // bucket2: action = add_int_field + output, inc_int_ttl at data plane (src node).
        TrafficTreatment.Builder trafficTreatment_bucket2 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket2 = new ArrayList<>();
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_BASE, (short) 24, mapInfo).action();
        OFAction action_output2 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, out_port2).action();
        actions_bucket2.add(action_add_int_field);
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action(); // for path revalidation
            actions_bucket2.add(action_add_func_field);
        }
//        actions_bucket2.add(action_inc_INT_ttl);   // no need inc_INT_ttl here, we directly set it at src node.
        actions_bucket2.add(action_output2);
        trafficTreatment_bucket2.add(DefaultPofInstructions.applyActions(actions_bucket2));

        // bucket2: weight2 -- int-operation
        GroupBucket bucket2 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket2.build(), weight2);

        // buckets
        GroupBuckets select_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription select_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.SELECT, select_group_buckets, old_key, select_group_id.id(), appId);


        /* this is add a new group table. */
//        groupService.addGroup(select_group);
//        log.info("Add select group table to deviceId<{}>, groupId<{}>, w1:w2={}:{}", deviceId.toString(), groupId, weight1, weight2);

        /* this is modify a exsisting group table. */
        byte[] new_keyData = new_key_str.getBytes();
        final GroupKey new_key = new DefaultGroupKey(new_keyData);
        GroupBuckets new_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));
        groupService.setBucketsForGroup(deviceId, old_key, new_buckets, new_key, appId);
        log.info("Modify select group table to deviceId<{}>, groupId<{}>, w1:w2={}:{}", deviceId.toString(), groupId, weight1, weight2);
    }

    /* sel_group at sw2, all buckets do INT operation. */
    public void install_pof_select_group_rule_at_sw2(DeviceId deviceId, byte tableId, int out_port1, int out_port2, String srcIP,
                                              String key_str, int groupId, int priority,
                                              short weight1, short weight2, String mapInfo) {
        GroupId select_group_id = new GroupId(groupId);

        byte[] keyData = key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);

        // modify INT-ttl
        short int_field_id = -1;
        OFMatch20 Field_INT_ttl =  new OFMatch20();
        Field_INT_ttl.setFieldName("INT_ttl");
        Field_INT_ttl.setFieldId(INT_TTL);
        Field_INT_ttl.setOffset(INT_HEADER_TTL_OFF);
        Field_INT_ttl.setLength(INT_HEADER_TTL_LEN);
        OFAction action_inc_INT_ttl = DefaultPofActions.modifyField(Field_INT_ttl, 1).action();
        OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action(); // for path revalidation

        // bucket1: action = add_int_field + inc_int_ttl + output:out_port1
        TrafficTreatment.Builder trafficTreatment_bucket1 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket1 = new ArrayList<>();
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, (short) 16, mapInfo).action();
        OFAction action_output1 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, out_port1).action();
        actions_bucket1.add(action_add_int_field);
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            actions_bucket1.add(action_add_func_field);
        }
        actions_bucket1.add(action_inc_INT_ttl);
        actions_bucket1.add(action_output1);
        trafficTreatment_bucket1.add(DefaultPofInstructions.applyActions(actions_bucket1));

        // bucket1: weight1 -- output
        GroupBucket bucket1 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket1.build(), weight1);

        // bucket2: action = add_int_field + inc_int_ttl + output:out_port2
        TrafficTreatment.Builder trafficTreatment_bucket2 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket2 = new ArrayList<>();
//        OFAction action_add_int_field2 = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, (short) 16, mapInfo).action();
        OFAction action_output2 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, out_port2).action();
        actions_bucket2.add(action_add_int_field);
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            actions_bucket2.add(action_add_func_field);
        }
        actions_bucket2.add(action_inc_INT_ttl);
        actions_bucket2.add(action_output2);
        trafficTreatment_bucket2.add(DefaultPofInstructions.applyActions(actions_bucket2));

        // bucket2: weight2 -- int-operation
        GroupBucket bucket2 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket2.build(), weight2);

        // buckets
        GroupBuckets select_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription select_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.SELECT, select_group_buckets, key, select_group_id.id(), appId);

        groupService.addGroup(select_group);
        log.info("Add select group table at sw2, deviceId<{}> groupId<{}>", deviceId.toString(), groupId);
    }

    /* sel_group at sw2, all buckets do INT operation. */
    public void install_mod_pof_select_group_rule_at_sw2(DeviceId deviceId, byte tableId, int out_port1, int out_port2, String srcIP,
                                                     String old_key_str, String new_key_str, int groupId, int priority,
                                                     short weight1, short weight2, String mapInfo) {
        GroupId select_group_id = new GroupId(groupId);

        byte[] keyData = old_key_str.getBytes();
        final GroupKey old_key = new DefaultGroupKey(keyData);

        // modify INT-ttl
        short int_field_id = -1;
        OFMatch20 Field_INT_ttl =  new OFMatch20();
        Field_INT_ttl.setFieldName("INT_ttl");
        Field_INT_ttl.setFieldId(INT_TTL);
        Field_INT_ttl.setOffset(INT_HEADER_TTL_OFF);
        Field_INT_ttl.setLength(INT_HEADER_TTL_LEN);
        OFAction action_inc_INT_ttl = DefaultPofActions.modifyField(Field_INT_ttl, 1).action();
        OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action(); // for path revalidation

        // bucket1: action = add_int_field + inc_int_ttl + output:out_port1
        TrafficTreatment.Builder trafficTreatment_bucket1 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket1 = new ArrayList<>();
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, (short) 16, mapInfo).action();
        OFAction action_output1 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, out_port1).action();
        actions_bucket1.add(action_add_int_field);
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            actions_bucket1.add(action_add_func_field);
        }
        actions_bucket1.add(action_inc_INT_ttl);
        actions_bucket1.add(action_output1);
        trafficTreatment_bucket1.add(DefaultPofInstructions.applyActions(actions_bucket1));

        // bucket1: weight1 -- output
        GroupBucket bucket1 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket1.build(), weight1);

        // bucket2: action = add_int_field + inc_int_ttl + output:out_port2
        TrafficTreatment.Builder trafficTreatment_bucket2 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket2 = new ArrayList<>();
//        OFAction action_add_int_field2 = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, (short) 16, mapInfo).action();
        OFAction action_output2 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, out_port2).action();
        actions_bucket2.add(action_add_int_field);
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            actions_bucket2.add(action_add_func_field);
        }
        actions_bucket2.add(action_inc_INT_ttl);
        actions_bucket2.add(action_output2);
        trafficTreatment_bucket2.add(DefaultPofInstructions.applyActions(actions_bucket2));

        // bucket2: weight2 -- int-operation
        GroupBucket bucket2 = DefaultGroupBucket.createSelectGroupBucket(trafficTreatment_bucket2.build(), weight2);

        // buckets
        GroupBuckets select_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription select_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.SELECT, select_group_buckets, old_key, select_group_id.id(), appId);

        /* this is add a new group table. */
//        groupService.addGroup(select_group);
//        log.info("Add select group table to deviceId<{}>, groupId<{}>, w1:w2={}:{}", deviceId.toString(), groupId, weight1, weight2);

        /* this is modify a exsisting group table. */
        byte[] new_keyData = new_key_str.getBytes();
        final GroupKey new_key = new DefaultGroupKey(new_keyData);
        GroupBuckets new_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));
        groupService.setBucketsForGroup(deviceId, old_key, new_buckets, new_key, appId);
        log.info("Modify select group table at sw2 to deviceId<{}>, groupId<{}>, w1:w2={}:{}", deviceId.toString(), groupId, weight1, weight2);
    }

    /* used to test collector performance */
    public void install_pof_all_group_rule_match_srcIP(DeviceId deviceId, byte tableId, String srcIP,String key_str, int groupId,
                                              int priority, int usr_port, int collect_port, String mapInfo) {
        GroupId select_group_id = new GroupId(groupId);

        byte[] keyData = key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);

        // bucket1: output
        TrafficTreatment.Builder trafficTreatment_bucket1 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket1 = new ArrayList<>();
        OFAction action_output1 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, usr_port).action();
        actions_bucket1.add(action_output1);
        trafficTreatment_bucket1.add(DefaultPofInstructions.applyActions(actions_bucket1));

        // bucket1: weight
        GroupBucket bucket1 = DefaultGroupBucket.createAllGroupBucket(trafficTreatment_bucket1.build());

        // bucket2: action: add_int_field + output
        short del_int_off = INT_HEADER_BASE;
        short del_int_len = -1;   // means sw read 'mapInfo' from pkts and get the real deleted len.
        short int_field_id = -1;
        TrafficTreatment.Builder trafficTreatment_bucket2 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket2 = new ArrayList<>();
//        OFAction action_set_dstIp2 = DefaultPofActions.setField(DIP, (short) 240, (short) 32, "0a020202", "ffffffff").action();
//        OFAction action_add_field1 = DefaultPofActions.addField(TEST, (short) 272, (short) 24, "090802").action();
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, (short) 272, (short) 16, mapInfo).action();
//        OFAction action_delete_field = DefaultPofActions.deleteField((short) 272, 16).action();
//        OFAction action_del_int_field = DefaultPofActions.deleteField(del_int_off, del_int_len).action();
        OFAction action_output2 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, collect_port).action();
//        actions_bucket2.add(action_set_dstIp2);
//        actions_bucket2.add(action_delete_field);
        actions_bucket2.add(action_add_int_field);   // {off, len} no meaning
//        actions_bucket2.add(action_add_field1);
//        actions_bucket2.add(action_del_int_field);
        actions_bucket2.add(action_output2);
        trafficTreatment_bucket2.add(DefaultPofInstructions.applyActions(actions_bucket2));

        // bucket2: weight
        GroupBucket bucket2 = DefaultGroupBucket.createAllGroupBucket(trafficTreatment_bucket2.build());

        // buckets:
        GroupBuckets all_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription all_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.ALL, all_group_buckets, key, select_group_id.id(), appId);

        groupService.addGroup(all_group);
        log.info("Add all group table");

    }

    public void install_pof_all_group_rule_match_type(DeviceId deviceId, byte tableId, String int_type,String key_str, int groupId,
                                           int priority, int usr_port, int collect_port, String mapInfo) {
        GroupId select_group_id = new GroupId(groupId);

        byte[] keyData = key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);

        // bucket1: output
        TrafficTreatment.Builder trafficTreatment_bucket1 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket1 = new ArrayList<>();

        // add-int-field
        short int_field_id = -1;
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, INT_HEADER_TYPE_LEN, mapInfo).action(); // 'mapInfo' should be 0xff
        OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action(); // for path revalidation

        // modify INT-ttl
        OFMatch20 Field_INT_ttl =  new OFMatch20();
        Field_INT_ttl.setFieldName("INT_ttl");
        Field_INT_ttl.setFieldId(INT_TTL);
        Field_INT_ttl.setOffset(INT_HEADER_TTL_OFF);
        Field_INT_ttl.setLength(INT_HEADER_TTL_LEN);
        OFAction action_inc_INT_ttl = DefaultPofActions.modifyField(Field_INT_ttl, 1).action();

        OFAction action_output1 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, collect_port).action();
        actions_bucket1.add(action_add_int_field);    /* add int metadata. */
        if (TEST_PATH_RAVALIDATION && TEST_PATH_FUNCTION) {
            actions_bucket1.add(action_add_func_field);  /* This action used to revalidate path. */
        }
        actions_bucket1.add(action_inc_INT_ttl);      /* increment int_ttl field by 1 */
        actions_bucket1.add(action_output1);
        trafficTreatment_bucket1.add(DefaultPofInstructions.applyActions(actions_bucket1));

        // bucket1: weight
        GroupBucket bucket1 = DefaultGroupBucket.createAllGroupBucket(trafficTreatment_bucket1.build());

        // bucket2: action: del_int_field + output
        short del_int_off = INT_HEADER_BASE;
        short del_int_len = -1;   // means sw read 'mapInfo' from pkts and get the real deleted len.
        TrafficTreatment.Builder trafficTreatment_bucket2 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket2 = new ArrayList<>();
        OFAction action_del_int_field = DefaultPofActions.deleteField(del_int_off, del_int_len).action();
        OFAction action_output2 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, usr_port).action();
        actions_bucket2.add(action_del_int_field);
        actions_bucket2.add(action_output2);
        trafficTreatment_bucket2.add(DefaultPofInstructions.applyActions(actions_bucket2));

        // bucket2: weight
        GroupBucket bucket2 = DefaultGroupBucket.createAllGroupBucket(trafficTreatment_bucket2.build());

        // buckets:
        GroupBuckets all_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription all_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.ALL, all_group_buckets, key, select_group_id.id(), appId);

        groupService.addGroup(all_group);
        log.info("Add all group table to deviceiId<{}> groupId<{}>", deviceId.toString(), groupId);

    }

    /* sw2, all buckets do INT operation. */
    public void install_pof_all_group_rule_match_type_at_sw2(DeviceId deviceId, byte tableId, String int_type,String key_str, int groupId,
                                                      int priority, int usr_port, int collect_port, String mapInfo) {
        GroupId select_group_id = new GroupId(groupId);

        byte[] keyData = key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);

        // bucket1: output
        TrafficTreatment.Builder trafficTreatment_bucket1 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket1 = new ArrayList<>();

        // add-int-field
        short int_field_id = -1;
        OFAction action_add_int_field = DefaultPofActions.addField(int_field_id, INT_HEADER_DATA_OFF, INT_HEADER_TYPE_LEN, mapInfo).action(); // 'mapInfo' should be 0xff
        OFAction action_add_func_field = DefaultPofActions.addField(TEST, INT_DATA_DPID_END_OFF, (short) 8, funcByteHexStr(deviceId)).action(); // for path revalidation

        // modify INT-ttl
        OFMatch20 Field_INT_ttl =  new OFMatch20();
        Field_INT_ttl.setFieldName("INT_ttl");
        Field_INT_ttl.setFieldId(INT_TTL);
        Field_INT_ttl.setOffset(INT_HEADER_TTL_OFF);
        Field_INT_ttl.setLength(INT_HEADER_TTL_LEN);
        OFAction action_inc_INT_ttl = DefaultPofActions.modifyField(Field_INT_ttl, 1).action();

        OFAction action_output1 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, collect_port).action();
        actions_bucket1.add(action_add_int_field);    /* add int metadata. */
        if (TEST_PATH_RAVALIDATION) {
            actions_bucket1.add(action_add_func_field);  /* This action used to revalidate path. */
        }
        actions_bucket1.add(action_inc_INT_ttl);      /* increment int_ttl field by 1 */
        actions_bucket1.add(action_output1);
        trafficTreatment_bucket1.add(DefaultPofInstructions.applyActions(actions_bucket1));

        // bucket1: weight
        GroupBucket bucket1 = DefaultGroupBucket.createAllGroupBucket(trafficTreatment_bucket1.build());

        // bucket2: action: add_int_field (auto-run-bucket1, then run bucket2) + output
        TrafficTreatment.Builder trafficTreatment_bucket2 = DefaultTrafficTreatment.builder();
        List<OFAction> actions_bucket2 = new ArrayList<>();
        OFAction action_output2 = DefaultPofActions.output((short) 0, (short) 0, (short) 0, usr_port).action();
//        actions_bucket2.add(action_add_int_field);    /* add int metadata. */
//        actions_bucket2.add(action_add_func_field);  /* This action used to revalidate path. */
//        actions_bucket2.add(action_inc_INT_ttl);      /* increment int_ttl field by 1 */
        actions_bucket2.add(action_output2);
        trafficTreatment_bucket2.add(DefaultPofInstructions.applyActions(actions_bucket2));

        // bucket2: weight
        GroupBucket bucket2 = DefaultGroupBucket.createAllGroupBucket(trafficTreatment_bucket2.build());

        // buckets:
        GroupBuckets all_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription all_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.ALL, all_group_buckets, key, select_group_id.id(), appId);

        groupService.addGroup(all_group);
        log.info("Add all group table at sw2");

    }


    public void remove_pof_group_tables(DeviceId deviceId, String key_str) {
        byte[] keyData = key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);
        groupService.removeGroup(deviceId, key, appId);
        log.info("remove group table deviceId <>.", deviceId.toString());
    }

    public void install_pof_write_metadata_from_packet_entry(DeviceId deviceId, int tableId, int next_table_id,
                                                             String srcIP, int priority) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // metadata bits
        short metadata_offset = 32;
        short udp_len_offset = 304;    // the offset of `len` field in udp
        short write_len = 16;          // the length of `len` field in udp

        // next_table_match_field (should same as next_table), here is still srcIP
        OFMatch20 next_table_match_srcIP = new OFMatch20();
        next_table_match_srcIP.setFieldId(SIP);
        next_table_match_srcIP.setFieldName("srcIP");
        next_table_match_srcIP.setOffset((short) 208);
        next_table_match_srcIP.setLength((short) 32);

        ArrayList<OFMatch20> match20List = new ArrayList<>();
        match20List.add(next_table_match_srcIP);

        byte next_table_match_field_num = 1;
        short next_table_packet_offset = 0;

        // instruction
        TrafficTreatment.Builder trafficTreatment = DefaultTrafficTreatment.builder();
        trafficTreatment.add(DefaultPofInstructions
                .writeMetadataFromPacket(metadata_offset, udp_len_offset, write_len));
        trafficTreatment.add(DefaultPofInstructions
                .gotoTable((byte) next_table_id, next_table_match_field_num, next_table_packet_offset, match20List));
//                .gotoDirectTable((byte) next_table_id, (byte) 0, (short) 0, 0, new OFMatch20()));

        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreatment.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());
    }

    public void install_pof_add_vlc_header_entry(DeviceId deviceId, int tableId, String srcIP, int outport, int priority,
                                             byte timeSlot, short ledId, short ueId, short serviceId) {
        // vlc header
        short type = 0x1918;
        short len = 0x000b;      // type:2 + len:2 + ts:1 + ledID:2 + ueID:2 + serviceId:2 = 11
        short vlc_offset = 336;  // begin of udp payload: 42*8=336 bits
        short vlc_length = 88;   // 11 * 8 bits
        short VLC = 0x16;

        // metadata bits
        short metadata_offset = 32;
        short write_len = 16;

        // vlc_header
        StringBuilder vlc_header = new StringBuilder();
        vlc_header.append(short2HexStr(type));
        vlc_header.append(short2HexStr(len));
        vlc_header.append(byte2HexStr(timeSlot));
        vlc_header.append(short2HexStr(ledId));
        vlc_header.append(short2HexStr(ueId));
        vlc_header.append(short2HexStr(serviceId));

        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        ArrayList<Criterion> matchList = new ArrayList<>();
        matchList.add(Criteria.matchOffsetLength(SIP, (short) 208, (short) 32, srcIP, "ffffffff"));
        trafficSelector.add(Criteria.matchOffsetLength(matchList));

        // action: add vlc header
        TrafficTreatment.Builder trafficTreatment = DefaultTrafficTreatment.builder();
        List<OFAction> actions = new ArrayList<>();
        OFAction action_add_vlc_field = DefaultPofActions.addField(VLC, vlc_offset, vlc_length, vlc_header.toString())
                .action();

        // used for set_field_from_metadata
        OFMatch20 metadata_udp_len = new OFMatch20();
        metadata_udp_len.setFieldName("metadata_udp_len");
        metadata_udp_len.setFieldId(OFMatch20.METADATA_FIELD_ID);
        metadata_udp_len.setOffset((short) (vlc_offset + 16));     // the packet_field_offset
        metadata_udp_len.setLength(write_len);                     // the packet_field_len

        // used for modify_field
        OFMatch20 vlc_len_field = new OFMatch20();
        vlc_len_field.setFieldName("vlc_len");
        vlc_len_field.setFieldId(len);
        vlc_len_field.setOffset((short) (vlc_offset + 16));
        vlc_len_field.setLength((short) 16);

        // vlc_len = vlc.header + udp.payload, so metadata minus udp.header
        short vlc_len = (short) (len - 8);
        OFAction action_set_vlc_len = DefaultPofActions.setFieldFromMetadata(metadata_udp_len, metadata_offset)
                .action();
        OFAction action_inc_vlc_len = DefaultPofActions.modifyField(vlc_len_field, vlc_len)
                .action();
        OFAction action_output = DefaultPofActions.output((short) 0, (short) 0, (short) 0, outport)
                .action();

        actions.add(action_add_vlc_field);
        actions.add(action_set_vlc_len);
        actions.add(action_inc_vlc_len);
        actions.add(action_output);
        trafficTreatment.add(DefaultPofInstructions.applyActions(actions));

        // get existed flow rules in flow table. if the dstIp equals, then delete it
        Map<Integer, FlowRule> existedFlowRules = new HashMap<>();
        existedFlowRules = flowTableStore.getFlowEntries(deviceId, FlowTableId.valueOf(tableId));
        if(existedFlowRules != null) {
            for(Integer flowEntryId : existedFlowRules.keySet()) {
                log.info("existedFlowRules.get(flowEntryId).selector().equals(trafficSelector.build()) ==> {}",
                        existedFlowRules.get(flowEntryId).selector().equals(trafficSelector.build()));
                if(existedFlowRules.get(flowEntryId).selector().equals(trafficSelector.build())) {
                    flowTableService.removeFlowEntryByEntryId(deviceId, tableId, flowEntryId);
                }
            }
        }

        long newFlowEntryId = flowTableStore.getNewFlowEntryId(deviceId, tableId);
        FlowRule.Builder flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreatment.build())
                .withPriority(priority)
                .withCookie(newFlowEntryId)
                .makePermanent();
        flowRuleService.applyFlowRules(flowRule.build());
    }


    public void install_openflow_output_FlowRule(DeviceId deviceId, byte tableId, String srcIP, int outport) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
//         trafficSelector.matchInPort(PortNumber.portNumber(1));

        IpPrefix ipPrefixValue = IpPrefix.valueOf(srcIP);
        trafficSelector.matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPSrc(ipPrefixValue);

        // action: packet in to controller
        TrafficTreatment.Builder trafficTreatment = DefaultTrafficTreatment.builder();
        PortNumber out_port = PortNumber.portNumber(outport);
        trafficTreatment.setOutput(out_port)
                        .build();

        // apply
        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreatment.build())
                .withPriority(0)
                .fromApp(appId)
                .makePermanent()
                .build();
        flowRuleService.applyFlowRules(flowRule);
    }

    public void installGroupActionFlowRule(DeviceId deviceId, byte tableId, int group_id) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        trafficSelector.matchEthType(Ethernet.TYPE_IPV4)
                       .matchInPort(PortNumber.portNumber(1));

        // action: packet in to controller
        TrafficTreatment.Builder trafficTreatment = DefaultTrafficTreatment.builder();
        trafficTreatment.group(new GroupId(group_id))
                        .build();

        // apply
        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreatment.build())
                .withPriority(0)
                .fromApp(appId)
                .makePermanent()
                .build();
        flowRuleService.applyFlowRules(flowRule);
    }

    public void installSelectGroupFlowRule(DeviceId deviceId, byte tableId, String key_str, int group_id) {
        GroupId select_group_id1 = new GroupId(group_id);
        byte[] keyData = key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);

        // bucket1: action = mod_nw_src + output
        TrafficTreatment.Builder trafficTrement_bucket1 = DefaultTrafficTreatment.builder();
        trafficTrement_bucket1.setIpDst(IpAddress.valueOf("10.1.1.2"))
                              .setOutput(PortNumber.portNumber(2))
                              .build();
        short weight1 = 2;
        GroupBucket bucket1 = DefaultGroupBucket.createSelectGroupBucket(trafficTrement_bucket1.build(), weight1);

        // bucket2: action = mod_nw_dst + output
        TrafficTreatment.Builder trafficTrement_bucket2 = DefaultTrafficTreatment.builder();
        trafficTrement_bucket2.setIpDst(IpAddress.valueOf("10.2.2.2"))
                              .setOutput(PortNumber.portNumber(2))
                              .build();
        short weight2 = 3;
        GroupBucket bucket2 = DefaultGroupBucket.createSelectGroupBucket(trafficTrement_bucket2.build(), weight2);

        // buckets
        GroupBuckets select_group_buckets = new GroupBuckets(ImmutableList.of(bucket1, bucket2));

        // apply
        DefaultGroupDescription select_group = new DefaultGroupDescription(deviceId,
                GroupDescription.Type.SELECT, select_group_buckets, key, select_group_id1.id(), appId);
        groupService.addGroup(select_group);

    }

    public void removeGroupTables(DeviceId deviceId, String key_str) {
        byte[] keyData = key_str.getBytes();
        final GroupKey key = new DefaultGroupKey(keyData);
        groupService.removeGroup(deviceId, key, appId);
    }

    public void install_openflow_mod_nw_dst_rule(DeviceId deviceId, byte tableId) {
        // match
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        trafficSelector.matchEthType(Ethernet.TYPE_IPV4)
                        .matchInPort(PortNumber.portNumber(1));

        // action: packet in to controller
        TrafficTreatment.Builder trafficTreatment = DefaultTrafficTreatment.builder();
        trafficTreatment.setIpDst(IpAddress.valueOf("10.3.3.2"))
                        .setOutput(PortNumber.portNumber(2))
                        .build();

        // apply
        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .forTable(tableId)
                .withSelector(trafficSelector.build())
                .withTreatment(trafficTreatment.build())
                .withPriority(0)
                .fromApp(appId)
                .makePermanent()
                .build();
        flowRuleService.applyFlowRules(flowRule);
    }


    /**
     * util tools.
     */

    public String short2HexStr(short shortNum) {
        StringBuilder hex_str = new StringBuilder();
        byte[] b = new byte[2];
        b[1] = (byte) (shortNum & 0xff);
        b[0] = (byte) ((shortNum >> 8) & 0xff);

        return bytes_to_hex_str(b);
    }

    public String byte2HexStr(byte byteNum) {
        String hex = Integer.toHexString(   byteNum & 0xff);
        if (hex.length() == 1) {
            hex = '0' + hex;
        }
        return hex;
    }

    public String funcByteHexStr(DeviceId deviceId) {
        String device = deviceId.toString().substring(18, 20);   /* for 'pof:000000000000000x', get '0x' */
        byte dpid = Integer.valueOf(device).byteValue();
        int k = 2, b = 1;
        byte y = (byte) (k * dpid + b);   // simple linear function
        return byte2HexStr(y);
    }

    public String bytes_to_hex_str(byte[] b) {
        StringBuilder hex_str = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            String hex = Integer.toHexString(b[i] & 0xff);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            hex_str.append(hex);
        }
        return hex_str.toString();
    }

}
