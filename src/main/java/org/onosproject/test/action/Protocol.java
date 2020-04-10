package org.onosproject.test.action;

/**
 * @author tsf
 * @created 2020-04-10
 * @description protocol definition.
 */

public class Protocol {

    /**
     * IPv4 field ids.
     */
    final static short DMAC_ID = 1;
    final static short SMAC_ID = 2;
    final static short TYPE_ID = 3;
    final static short TTL_ID = 11;
    final static short SIP_ID = 12;
    final static short DIP_ID= 13;

    /**
     * INT header fields ids.
     */
    final static short INT_TYPE_ID = 15;
    final static short INT_TTL_ID = 16;

    final static short INT_FIELD_ID = -1;
    final static short INT_DPID_ID = 17;

    /**
     * IPv4 header in bits.
     */
    final static short ETH_HEADER_LEN = 14 * 8;
    final static short ETH_DMAC_OFF = 0;
    final static short ETH_DMAC_LEN = 6 * 8;
    final static short ETH_SMAC_OFF = 6 * 8;
    final static short ETH_SMAC_LEN = 6 * 8;

    final static short ETH_TYPE_OFF = 12 * 8;
    final static short ETH_TYPE_LEN = 2 * 8;

    final static short IPV4_HEADER_LEN = 20 * 8;
    final static short IPV4_TTL_OFF = 22 * 8;
    final static short IPV4_TTL_LEN = 8;

    final static short IPV4_SIP_OFF = 26 * 8;
    final static short IPV4_SIP_LEN = 4 * 8;
    final static short IPV4_DIP_OFF = 30 * 8;
    final static short IPV4_DIP_LEN = 4 * 8;

    /**
     * INT header in bits.
     */
    final static short INT_HEADER_BASE = 34 * 8;
    final static short INT_HEADER_LEN = 5 * 8;
    final static short INT_HEADER_TYPE_OFF = 34 * 8;
    final static short INT_HEADER_TYPE_LEN = 2 * 8;

    final static short INT_HEADER_TTL_OFF = 36 * 8;
    final static short INT_HEADER_TTL_LEN  = 8;
    final static short INT_HEADER_MAPINFO_OFF = 37 * 8;
    final static short INT_HEADER_MAPINFO_LEN = 2 * 8;

    final static short INT_HEADER_DATA_OFF = 39 * 8;
    final static short INT_DATA_DPID_END_OFF = 43 * 8;    // 39 + 4 = 42
    final static short INT_DATA_DPID_END_LEN = 8;         // path revalidation

    /**
     * INT header fields in bits.
     */
    final static short INT_DATA_DPID_LEN = 4 * 8;
    final static short INT_DATA_IN_PORT_LEN = 2 * 8;
    final static short INT_DATA_OUT_PORT_LEN = 2 * 8;
    final static short INT_DATA_INGRESS_TIME_LEN = 8 * 8;
    final static short INT_DATA_HOP_LATENCY_LEN = 4 * 8;

    final static short INT_DATA_BANDWIDTH_LEN = 4 * 8;
    final static short INT_DATA_N_PACKETS_LEN = 8 * 8;
    final static short INT_DATA_N_BYTES_LEN = 8 * 8;
    final static short INT_DATA_QUEUE_LEN = 4 * 8;
    final static short INT_DATA_FWD_ACTS = 2 * 8;

    /**
     * field values.
     */
    final static String IPV4_SIP_VAL = "0a000001";
    final static String INT_TYPE_VAL = "0908";
    final static String DATA_PLANE_MAPINFO_VAL = "ffff";   // "ffff" means read mapInfo from pkts

    /**
     * group table.
     */
    final static String all_key = "def";
    final static int all_groupId = 0x17;
}
