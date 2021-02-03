#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <pthread.h>
#include <cstring>
#include <list>
#include <ncurses.h>
#include <regex>
#include <unistd.h>
#include "netformat.h"

using namespace std;
#define BEACON_FRAME 8
#define HIDDEN_ESSID_LENGTH 11


#pragma pack(push, 1)
struct ApStatus {
    uint8_t     bssid[6];
    uint8_t     ant_signal;
    uint8_t     beacons;
    int         channel;
    u_char*     essid;
    int         essid_len;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ChThread {
    char       *dev;
    int        *ch_list;
};
#pragma pack(pop)

int CalcChannel(uint16_t freq) {
    if(freq >= 2412 && freq <= 2484) {
        if (freq == 2484)
            return (freq-2412)/5;
        return (freq-2412)/5 + 1;
    }
    else if( freq >= 5170 && freq <= 5825) {
        return (freq-5170)/5 + 34;
    }
    else {
        return -1;
    }
}

class ApTable {
    list<ApStatus> ap_list;
    list<ApStatus>::iterator ap_it;

public:
    ApTable() {
        initscr();
    }
    ~ApTable() {
        endwin();
        list<ApStatus>::iterator it;
        for (it = ap_list.begin();it != ap_list.end();it++) {
            delete it->essid;
        }
    }
    bool IsInList(uint8_t bssid[]) {
        list<ApStatus>::iterator it;
        for (it = ap_list.begin();it != ap_list.end();it++) {
            if(memcmp(it->bssid, bssid, 6) == 0){
                ap_it = it;
                return true;
            }
        }
        return false;
    }
    void AddList(ApStatus *ap_stat) {
        ap_list.push_back(*ap_stat);
        PrintList();
    }
    void UpdateList(uint8_t sig) {
        ap_it->ant_signal = sig;
        ap_it->beacons += 1;
        ap_list.splice(ap_list.begin(),ap_list,ap_it);
        PrintList();
    }
    void PrintList() {
        list<ApStatus>::iterator it;
        int i = 5;
        clear();
        mvprintw(3,1,"BSSID               PWR           Beacons      CH    ESSID");
        for (it = ap_list.begin();it != ap_list.end();it++) {
            mvprintw(i,1,"%02x:%02X:%02X:%02X:%02X:%02X", it->bssid[0], it->bssid[1], it->bssid[2], it->bssid[3], it->bssid[4], it->bssid[5]);
            mvprintw(i,21,"%d    \n",it->ant_signal-0x100);
            mvprintw(i,35,"%d    \n",it->beacons);
            mvprintw(i,48,"%d    \n",it->channel);
            mvprintw(i,54,"%.*s\n",it->essid_len, it->essid);
            i++;
        }
        refresh();
    }
};

void GetChannelList(char *dev, int **ch_list) {
    char *cmd = new char[48];
    sprintf(cmd, "iwlist %s channel", dev);

    FILE *fp = popen(cmd, "r");
    if(fp == nullptr) {
        printf("popen error\n");
        printf("command is %s\n", cmd);
        exit(-1);
    }

    char *tmp = new char[4000];
    fread(tmp, 4000, 1, fp);
    string buf(tmp);
    regex reg(" ([0-9])+ ");
    sregex_iterator it_begin(buf.begin(), buf.end(), reg);
    sregex_iterator it_end;
    int i = 0;
    for (sregex_iterator it = it_begin;it != it_end;it++, i++) {
        smatch match = *it;
        string match_str = match.str();
        if(i == 0) {
            int ch_num = stoi(match_str);
            *ch_list = new int[ch_num+1];
            (*ch_list)[ch_num] = 0;
        }
        else {
            int ch = stoi(match_str);
            (*ch_list)[i-1] = ch;
        }
    }
    delete []cmd;
    delete []tmp;
}

void *ChannelHopping(void *thd) {
    ChThread *p = reinterpret_cast<ChThread*>(thd);
    char *cmd = new char[48];
    int i = 0;
    while (true) {
        if(p->ch_list[i] == 0)
            i = 0;
        sprintf(cmd, "iwconfig %s channel %d", p->dev, p->ch_list[i]);
        system(cmd);
        mvprintw(1,1,"CH  %03d  ]", p->ch_list[i]);
        refresh();
        i++;
    }
}

void Usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodumo mon0\n");
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        Usage();
        return -1;
    }
    class ApTable ap_table;
    int type = 0;
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pthread_t p_thread;
    ChThread ch_thd;
    ch_thd.dev = argv[1];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    GetChannelList(dev, &ch_thd.ch_list);
    pthread_create(&p_thread, nullptr, ChannelHopping, &ch_thd);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        RadiotapHeader *radioh = reinterpret_cast<RadiotapHeader*>(const_cast<u_char*>(packet));
        RadiotapAddHeader *radioaddh = reinterpret_cast<RadiotapAddHeader*>(const_cast<u_char*>(packet + sizeof(RadiotapHeader)));
        BeaconHeader *beaconh = reinterpret_cast<BeaconHeader*>(const_cast<u_char*>(packet += radioh->h_len));
        type = beaconh->type << 4 ^ beaconh->sub_type;
        if(type != BEACON_FRAME)
            continue;

        if(ap_table.IsInList(beaconh->bssid)) {
            ap_table.UpdateList(radioaddh->ant_signal);
        }
        else {
            WirelessHeader *wirelessh = reinterpret_cast<WirelessHeader*>(const_cast<u_char*>(packet += sizeof(BeaconHeader)));
            ApStatus ap_st;
            memcpy(ap_st.bssid, beaconh->bssid, 6);
            ap_st.beacons = 1;
            ap_st.ant_signal = radioaddh->ant_signal;
            ap_st.channel = CalcChannel(radioaddh->ch_frequency);
            if((memchr(const_cast<u_char*>(packet+sizeof (WirelessHeader)), '\0', 1) != nullptr) || wirelessh->ssid_tag_len == 0) {
                ap_st.essid_len = (wirelessh->ssid_tag_len/10) + HIDDEN_ESSID_LENGTH;
                ap_st.essid = new u_char[ap_st.essid_len];
                sprintf(reinterpret_cast<char*>(ap_st.essid), "<length: %d>", wirelessh->ssid_tag_len);
            }
            else {
                ap_st.essid_len = wirelessh->ssid_tag_len;
                ap_st.essid = new u_char[ap_st.essid_len];
                memcpy(ap_st.essid, const_cast<u_char*>(packet+sizeof (WirelessHeader)), wirelessh->ssid_tag_len);
            }
            ap_table.AddList(&ap_st);
        }
    }
    delete []ch_thd.ch_list;
    pcap_close(pcap);
}

