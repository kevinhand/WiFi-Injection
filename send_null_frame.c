/**
 * Hello, and welcome to this brief, but hopefully complete, example file for
 * wireless packet injection using pcap.
 *
 * Although there are various resources for this spread on the web, it is hard
 * to find a single, cohesive piece that shows how everything fits together.
 * This file aims to give such an example, constructing a fully valid UDP packet
 * all the way from the 802.11 PHY header (through radiotap) to the data part of
 * the packet and then injecting it on a wireless interface
 *
 * Skip down a couple of lines, as the following is just headers and such that
 * we need.
 */
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


/* Defined in include/linux/ieee80211.h */
struct ieee80211_hdr {
  uint16_t /*__le16*/ frame_control;
  uint16_t /*__le16*/ duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t /*__le16*/ seq_ctrl;
  //uint8_t addr4[6];
} __attribute__ ((packed));

#define WLAN_FC_TYPE_DATA	2
#define WLAN_FC_SUBTYPE_NULL	4


/*************************** START READING AGAIN ******************************/




/**
 * Radiotap is a protocol of sorts that is used to convey information about the
 * physical-layer part of wireless transmissions. When monitoring an interface
 * for packets, it will contain information such as what rate was used, what
 * channel it was sent on, etc. When injecting a packet, we can use it to tell
 * the 802.11 card how we want the frame to be transmitted.
 *
 * The format of the radiotap header is somewhat odd.
 * include/net/ieee80211_radiotap.h does an okay job of explaining it, but I'll
 * try to give a quick overview here.
 *
 * Keep in mind that all the fields here are little-endian, so you should
 * reverse the order of the bytes in your head when reading. Also, fields that
 * are set to 0 just mean that we let the card choose what values to use for
 * that option (for rate and channel for example, we'll let the card decide).
 */
static const uint8_t u8aRadiotapHeader[] = {

  0x00, 0x00, // <-- radiotap version (ignore this)
  0x0d, 0x00, // <-- number of bytes in our header (count the number of "0x"s)

  /**
   * The next field is a bitmap of which options we are including.
   * The full list of which field is which option is in ieee80211_radiotap.h,
   * but I've chosen to include:
   *   0x00 0x01: timestamp
   *   0x00 0x02: flags
   *   0x00 0x03: rate
   *   0x00 0x04: channel
   *   0x80 0x00: tx flags (seems silly to have this AND flags, but oh well)
   */
  0x04, 0x80, 0x02, 0x00,
//  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp

  /**
   * This is the first set of flags, and we've set the bit corresponding to
   * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the end
   * of our buffer for us.
   */
//  0x00,

  0x02, // <-- rate

//  0x6c, 0x09, 0xc0, 0x00, // <-- channel
//  0xd3, 0x01,//ssi, antenna
  0x00, 0x01,
  /**
   * This is the second set of flags, specifically related to transmissions. The
   * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
   * wait for an ACK for this frame, and that it won't retry if it doesn't get
   * one.
   */
  0x00, 0x00,
};


int main(void) {

  /* The parts of our packet */
  uint8_t *rt; /* radiotap */
  struct ieee80211_hdr *hdr;


  /* Other useful bits */
  uint8_t *buf;
  size_t sz;
  uint8_t fcchunk[2]; /* 802.11 header frame control */


  /* PCAP vars */
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap;
  
  /* Total buffer size (note the 0 bytes of data and the 4 bytes of FCS */
  sz = sizeof(u8aRadiotapHeader) + sizeof(struct ieee80211_hdr);
  buf = (uint8_t *) malloc(sz);

  /* Put our pointers in the right place */
  rt = (uint8_t *) buf;
  hdr = (struct ieee80211_hdr *) (rt+sizeof(u8aRadiotapHeader));

  /* The radiotap header has been explained already */
  memcpy(rt, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));

  /**
   * Next, we need to construct the 802.11 header
   *
   * The biggest trick here is the frame control field.
   * http://www.wildpackets.com/resources/compendium/wireless_lan/wlan_packets
   * gives a fairly good explanation.
   *
   * The first byte of the FC gives the type and "subtype" of the 802.11 frame.
   * We're transmitting a data frame, so we set both the type and the subtype to
   * DATA.
   *
   * Most guides also forget to mention that the bits *within each byte* in the
   * FC are reversed (!!!), so FROMDS is actually the *second to last* bit in
   * the FC, hence 0x02.
   */
  fcchunk[0] = ((WLAN_FC_TYPE_DATA << 2) | (WLAN_FC_SUBTYPE_NULL << 4));
  fcchunk[1] = 0x02;
  memcpy(&hdr->frame_control, &fcchunk[0], 2*sizeof(uint8_t));

  /**
   * The remaining fields are more straight forward.
   * The duration we can set to some arbitrary high number, and the sequence
   * number can safely be set to 0.
   * The addresses here can be set to whatever, but bear in mind that which
   * address corresponds to source/destination/BSSID will vary depending on
   * which of TODS and FROMDS are set. The full table can be found at the
   * wildpackets.com link above, or condensed here:
   *
   *  +-------+---------+-------------+-------------+-------------+-----------+
   *  | To DS | From DS | Address 1   | Address 2   | Address 3   | Address 4 |
   *  +-------+---------+-------------+-------------+-------------+-----------+
   *  |     0 |       0 | Destination | Source      | BSSID       | N/A       |
   *  |     0 |       1 | Destination | BSSID       | Source      | N/A       |
   *  |     1 |       0 | BSSID       | Source      | Destination | N/A       |
   *  |     1 |       1 | Receiver    | Transmitter | Destination | Source    |
   *  +-------+---------+-------------+-------------+-------------+-----------+
   *
   * Also note that addr4 has been commented out. This is because it should not
   * be present unless both TODS *and* FROMDS has been set (as shown above).
   */
   
   
  /* A bogus MAC address just to show that it can be done */
 const uint8_t STA[6] = { 0xf8, 0xcf, 0xc5, 0xdb, 0x34, 0xdd };
// const uint8_t STA[6] = { 0xf4, 0x09, 0xd8, 0x9c, 0x4d, 0xc6 };
 const uint8_t AP[6] = { 0x10, 0xfe, 0xed, 0xb0, 0xbd, 0x78 };
   
  hdr->duration_id = 0xffff;
  memcpy(&hdr->addr1[0], STA, 6*sizeof(uint8_t));
  memcpy(&hdr->addr2[0], AP, 6*sizeof(uint8_t));
  memcpy(&hdr->addr3[0], AP, 6*sizeof(uint8_t));
  hdr->seq_ctrl = 0x7450;
  //hdr->addr4;


  /**
   * Finally, we have the packet and are ready to inject it.
   * First, we open the interface we want to inject on using pcap.
   */
  ppcap = pcap_open_live("wlan9", 400, 1, 20, errbuf);

  if (ppcap == NULL) {
    printf("Could not open interface wlan10 for packet injection: %s", errbuf);
    return 2;
  }

  /**
   * Then we send the packet and clean up after ourselves
   */
  if (pcap_sendpacket(ppcap, buf, sz) == 0) {
    pcap_close(ppcap);
    return 0;
  }

  /**
   * If something went wrong, let's let our user know
   */
  pcap_perror(ppcap, "Failed to inject packet");
  pcap_close(ppcap);
  return 1;
}

/**
 * And that's it - a complete wireless packet injection function using pcap!
 */

