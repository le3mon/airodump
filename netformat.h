#pragma once

#include <stdint.h>


#pragma pack(push, 1)
struct RadiotapHeader {
    uint8_t     h_ver;
    uint8_t     h_pad;
    uint16_t    h_len;
    uint32_t    present[3];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct RadiotapAddHeader {
    uint8_t     flags;
    uint8_t     rate;
    uint16_t    ch_frequency;
    uint16_t    ch_flags;
    uint8_t     ant_signal;
    uint8_t     pad;
    uint16_t    signal_quality;
    uint16_t    rx_flags;
    uint8_t     ant_signal_1;
    uint8_t     ant_1;
    uint8_t     ant_signal_2;
    uint8_t     ant_2;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct BeaconHeader {
    uint8_t     ver:2;
    uint8_t     type:2;
    uint8_t     sub_type:4;
    uint8_t     flag;
    uint16_t    duration;
    uint8_t     dest_addr[6];
    uint8_t     src_addr[6];
    uint8_t     bssid[6];
    uint16_t    fragment_num:4;
    uint16_t    sequence_num:12;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct WirelessHeader {
    uint64_t    timestamp;
    uint16_t    beacon_interval;
    uint16_t    capa_info;
    uint8_t     ssid_tag_num;
    uint8_t     ssid_tag_len;
};
#pragma pack(pop)
