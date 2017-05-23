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

#define WLAN_FC_TYPE_CONTROL	1
#define WLAN_FC_SUBTYPE_RTS	11


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
//  0xeb, 0x01,//ssi, antenna

  /**
   * This is the second set of flags, specifically related to transmissions. The
   * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
   * wait for an ACK for this frame, and that it won't retry if it doesn't get
   * one.
   */
//  0x00, 0x00,
  0x00, 0x01, 0x00, 0x04,
};


static const uint8_t u8aManagementFrame[] = {
	//Fixed parameters 12 bytes
	0xf6, 0xbf, 0xf6, 0x00, 0x00, 0x00, 0x00, 0x00,//timestamp
	0x64, 0x00,//beacon interval
	0x01, 0x04, // Capabilities information
	
	//Tagged parameter 122bytes
	//SSID parameter 12byte
	0x00,//tag number
	0x0a,//tag length
	0x53, 0x75, 0x70, 0x65, 0x72, 0x48, 0x61, 0x6e, 0x64, 0x65,//SSID SuperHande
	
	//Supported Rates 10bytes
	0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
	
	0x03, 0x01, 0x01, //DS parameter 3 
	
//	0x05, 0x04, 0x01, 0x02, 0x00, 0x00, //TIM 6
	
	0x2a, 0x01, 0x04, //ERP 3
	
	0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,//extended support rates 6 
	
	//HT capabilities 28 bytes
	0x2d, 0x1a, 
	0x0c, 0x00,
	0x13,
	0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
	0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00,
	
	//HT Information 24bytes
	0x3d, 0x16, 0x01, 0x00, 0x11, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	
	//Extended capability 10 
	0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
	
	//vendor specific 26bytes
	0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00,
	0x03, 0xa4, 0x00, 0x00, 
	0x27, 0xa4, 0x00, 0x00,
	0x42, 0x43, 0x5d, 0x00,
	0x62, 0x32, 0x2e, 0x00,
};


int main(void) {

  /* The parts of our packet */
  uint8_t *rt; /* radiotap */
  struct ieee80211_hdr *hdr;
  uint8_t *wlmf; // wireless management frame


  /* Other useful bits */
  uint8_t *buf;
  size_t sz;
  uint8_t fcchunk[2]; /* 802.11 header frame control */


  /* PCAP vars */
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap;
  
  /* Total buffer size (note the 0 bytes of data and the 4 bytes of FCS */
  sz = sizeof(u8aRadiotapHeader) + sizeof(struct ieee80211_hdr)+134;//management frame 140 bytes
  buf = (uint8_t *) malloc(sz);

  /* Put our pointers in the right place */
  rt = (uint8_t *) buf;
  hdr = (struct ieee80211_hdr *) (rt+sizeof(u8aRadiotapHeader));
  wlmf = (uint8_t *)(hdr+1);

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
  fcchunk[0] = 0x50;//(( WLAN_FC_TYPE_CONTROL << 2) | (WLAN_FC_SUBTYPE_RTS << 4));
  fcchunk[1] = 0x00;
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
 //const uint8_t STA[6] = { 0xf8, 0xcf, 0xc5, 0xdb, 0x34, 0xdd };
 
 const uint8_t STA[6] = { 0xf4, 0x09, 0xd8, 0x9c, 0x4d, 0xc6 };
// const uint8_t AP[6] = { 0xa4, 0x6c, 0x2a, 0x11, 0x02, 0x80 };
  const uint8_t BROADCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
//  const uint8_t AP[6] = { 0x10, 0xfe, 0xed, 0xb0, 0xbd, 0x77 };
const uint8_t AP[6] = { 0x48, 0xee, 0x0c, 0xc3, 0x9e, 0x23 };
   
  hdr->duration_id = 0x013a;
  memcpy(&hdr->addr1[0], STA, 6*sizeof(uint8_t));
  memcpy(&hdr->addr2[0], AP, 6*sizeof(uint8_t));
  memcpy(&hdr->addr3[0], AP, 6*sizeof(uint8_t));
  hdr->seq_ctrl = 0x85d0;
  //hdr->addr4;



//management frame construction
  memcpy(wlmf, u8aManagementFrame, sizeof(u8aManagementFrame));


  /**
   * Finally, we have the packet and are ready to inject it.
   * First, we open the interface we want to inject on using pcap.
   */
  ppcap = pcap_open_live("wlan9", 400, 1, 20, errbuf);

  if (ppcap == NULL) {
    printf("Could not open interface wlan3 for packet injection: %s", errbuf);
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

