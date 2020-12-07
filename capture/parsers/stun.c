/* 
Adds support to Moloch for parsing STUN traffic. 
https://git.digi.intern/150223/moloch-stun

-- Wiger van Houten, TDO Noord-Nederland, 09-11-2020
 */

#include "moloch.h"
#include <arpa/inet.h>

extern MolochConfig_t        config;

LOCAL  int typeField;
LOCAL  int xoripField;
LOCAL  int xorportField;

/******************************************************************************/
void stun_unxor4(unsigned char const *data, int *port, struct in_addr *in){
  int offset=20;

  // cookie = magic cookie
  unsigned char cookie[4];
  memcpy(cookie, data+4, 4);
  *port= ((uint32_t)( cookie[0]^data[offset+6] )) << 8 | ((uint32_t)( cookie[1]^data[offset+7] ));

  // holds the XOR'ed IP address
  unsigned char xaddr[4];
  memcpy(xaddr, data+offset+8, 4);

  in->s_addr = ((uint32_t)( (cookie[3]^xaddr[3])  )) << 24 | ((uint32_t)( (cookie[2]^xaddr[2]) )) << 16 | ((uint32_t)( (cookie[1]^xaddr[1]) )) << 8 | (cookie[0]^xaddr[0]);
}

/******************************************************************************/
void stun_unxor6(unsigned char const *data, int *port, struct in6_addr *in){
  int offset=20;

  // cookie = magic cookie + transactionid
  unsigned char cookie[16];
  memcpy(cookie, data+4, 4);
  memcpy(cookie+4, data+8, 12);
  *port= ((uint32_t)( (cookie[0]^data[offset+6]) )) << 8 | ((uint32_t)( (cookie[1]^data[offset+7]) ));

  // holds the XOR'ed IP address
  unsigned char xaddr[16];
  memcpy(xaddr, data+offset+8, 16);

  // holds the unxored IP address
  unsigned char ip[16];
  for (int j=0; j<16; j++){
    ip[j]=cookie[j]^xaddr[j];
  }

  memcpy(in->s6_addr, ip, 16);

}


/******************************************************************************/
//void stun_parser(MolochSession_t *session, void *uw, const unsigned char *data, int remaining)
LOCAL int stun_parser(MolochSession_t *session, void *UNUSED(uw), const unsigned char *data, int len, int UNUSED(which))
{
    if (memcmp(data, "\x00\x01", 2) == 0) {
      //LOG("Binding request!");
      moloch_field_string_add(typeField, session, "Binding request", 15, TRUE);
      return 0;
    }

    if (memcmp(data, "\x00\x03", 2) == 0) {
      //LOG("Allocate request!");
      moloch_field_string_add(typeField, session, "Allocate request", 16, TRUE);
      return 0;
    }

    if (memcmp(data, "\x01\x01", 2) == 0) {
      //LOG("Binding success response!");
      moloch_field_string_add(typeField, session, "Binding success response", 24, TRUE);
      // stun.type.message-assignment = 2
      // stun.length = 2
      // stun.cookie = 4
      // stun.id = 12
      //  total = 20
      int offset=20;

      // attribute length
      int atlen=0;

      // message length (does not include 20 byte header):
      int mlen=(data[2]<<8)+data[3];
      while (offset<mlen+20){
        //LOG("Start Offset: %i", offset);

        // check attribute type (2b):
        if (memcmp(data+offset, "\x00\x20", 2)==0){
          //LOG("XOR mapped address");
          if (memcmp(data+offset+5, "\x01", 1)==0){
            // address family ipv4
            int port;
            struct in_addr in;
            stun_unxor4(data, &port, &in);

            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(in.s_addr), str, INET_ADDRSTRLEN);

            //LOG(" XOR port = %i", port);
            moloch_field_int_add(xorportField, session, port);
            moloch_field_ip4_add(xoripField, session, in.s_addr);

            inet_ntop(AF_INET, &(in.s_addr), str, INET_ADDRSTRLEN);
            //LOG(" IP: %s", str);
          }
          if (memcmp(data+offset+5, "\x02", 1)==0){
            // address family ipv6
            int port;
            struct in6_addr in;
            stun_unxor6(data, &port, &in);

            char str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(in.s6_addr), str, INET6_ADDRSTRLEN);

            //LOG(" XOR6 port = %i", port);
            moloch_field_int_add(xorportField, session, port);
            moloch_field_ip6_add(xoripField, session, in.s6_addr);

            inet_ntop(AF_INET6, &(in.s6_addr), str, INET6_ADDRSTRLEN);
            //LOG(" IP6: %s", str);

          }
        }

        // check attribute length (2b):
        atlen=(data[offset+2]<<8)+data[offset+3];
        //LOG(" Attribute len: %i", atlen);
        offset=offset+atlen+4;
      }
      return 0;
    }

    if (memcmp(data, "\x01\x03", 2) == 0) {
      //LOG("Allocate success response!");
      moloch_field_string_add(typeField, session, "Allocate success response", 25, TRUE);
      int offset=20;
      // attribute length
      int atlen=0;

      // message length:
      int mlen=(data[2]<<8)+data[3];
      while (offset<mlen+20){
        //LOG("Start Offset: %i", offset);

        // check attribute type (2b):
        if (memcmp(data+offset, "\x00\x20", 2)==0){
          //LOG("XOR mapped address");
          if (memcmp(data+offset+5, "\x01", 1)==0){
            // address family ipv4
            int port;
            struct in_addr in;
            stun_unxor4(data, &port, &in);

            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(in.s_addr), str, INET_ADDRSTRLEN);

            //LOG(" XOR port = %i", port);
            moloch_field_int_add(xorportField, session, port);
            moloch_field_ip4_add(xoripField, session, in.s_addr);

            inet_ntop(AF_INET, &(in.s_addr), str, INET_ADDRSTRLEN);
            //LOG(" IP: %s", str);
          }
          if (memcmp(data+offset+5, "\x02", 1)==0){
            // address family ipv6
            int port;
            struct in6_addr in;
            stun_unxor6(data, &port, &in);

            char str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(in.s6_addr), str, INET6_ADDRSTRLEN);

            //LOG(" XOR6 port = %i", port);
            moloch_field_int_add(xorportField, session, port);
            moloch_field_ip6_add(xoripField, session, in.s6_addr);

            inet_ntop(AF_INET6, &(in.s6_addr), str, INET6_ADDRSTRLEN);
            //LOG(" IP6: %s", str);
          }
        }

        // check attribute length (2b):
        atlen=(data[offset+2]<<8)+data[offset+3];
        //LOG(" Attribute len: %i", atlen);
        offset=offset+atlen+4;
      }

      return 0;
    }
  return 0;
}


/******************************************************************************/
LOCAL void stun_classify(MolochSession_t *session, const unsigned char *data, int len, int UNUSED(which), void *UNUSED(uw))
{
    if (len < 20 || 20 + data[3] != len){
        return;
    }

    if (memcmp(data+4, "\x21\x12\xa4\x42", 4) == 0) {
        // Added:
        moloch_parsers_register(session, stun_parser, 0, 0);
        moloch_session_add_protocol(session, "stun");

    }

    return;
}

/******************************************************************************/
LOCAL void stun_rsp_classify(MolochSession_t *session, const unsigned char *data, int len, int UNUSED(which), void *UNUSED(uw))
{
    if (moloch_memstr((const char *)data+7, len-7, "STUN", 4))
        moloch_session_add_protocol(session, "stun");
}
/******************************************************************************/


#define CLASSIFY_TCP(name, offset, bytes, cb) moloch_parsers_classifier_register_tcp(name, name, offset, (unsigned char*)bytes, sizeof(bytes)-1, cb);
#define CLASSIFY_UDP(name, offset, bytes, cb) moloch_parsers_classifier_register_udp(name, name, offset, (unsigned char*)bytes, sizeof(bytes)-1, cb);

#define PARSERS_CLASSIFY_BOTH(_name, _uw, _offset, _str, _len, _func) \
    moloch_parsers_classifier_register_tcp(_name, _uw, _offset, (unsigned char*)_str, _len, _func); \
    moloch_parsers_classifier_register_udp(_name, _uw, _offset, (unsigned char*)_str, _len, _func);

#define SIMPLE_CLASSIFY_TCP(name, bytes) moloch_parsers_classifier_register_tcp(name, name, 0, (unsigned char*)bytes, sizeof(bytes)-1, misc_add_protocol_classify);
#define SIMPLE_CLASSIFY_UDP(name, bytes) moloch_parsers_classifier_register_udp(name, name, 0, (unsigned char*)bytes, sizeof(bytes)-1, misc_add_protocol_classify);
#define SIMPLE_CLASSIFY_BOTH(name, bytes) PARSERS_CLASSIFY_BOTH(name, name, 0, (unsigned char*)bytes, sizeof(bytes)-1, misc_add_protocol_classify);

void moloch_parser_init()
{

    typeField = moloch_field_define("stun", "termfield",
          "stun.type", "Type", "stun.type",
          "STUN typefield",
          MOLOCH_FIELD_TYPE_STR_GHASH,  MOLOCH_FIELD_FLAG_CNT,
          (char *)NULL);

    xoripField = moloch_field_define("stun", "ip",
          "stun.xorip", "STUN IP", "stun.xorip",
          "STUN IP XOR Mapped",
          MOLOCH_FIELD_TYPE_IP, MOLOCH_FIELD_FLAG_IPPRE,
          "category", "ip",
          (char *)NULL);

    xorportField = moloch_field_define("stun", "integer",
          "stun.xorport", "STUN Port", "stun.xorport",
          "STUN PORT XOR Mapped",
          MOLOCH_FIELD_TYPE_INT,  0,
          "category", "port",
          (char *)NULL);

    PARSERS_CLASSIFY_BOTH("stun", NULL, 0, (unsigned char*)"RSP/", 4, stun_rsp_classify);

    CLASSIFY_UDP("stun", 0, "\x00\x01\x00", stun_classify);
    CLASSIFY_UDP("stun", 0, "\x00\x03\x00", stun_classify);
    CLASSIFY_UDP("stun", 0, "\x01\x01\x00", stun_classify);

}
