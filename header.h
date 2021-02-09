#pragma once
#include <stdlib.h>
#include <arpa/inet.h>
#include <string>
#include<iostream>
#include "mac.h"
using namespace std;
#pragma pack(push, 1)
typedef struct radiotap_header {
        uint8_t        revision; 
        uint8_t        pad;
        uint16_t       length;    
        uint64_t       present_flags;    
        uint8_t        flags;
        uint8_t        data_Rate;
        uint16_t       channel_frequency;
        uint16_t       channel_flags;
        uint8_t        antenna_signal;
        uint8_t        dummy;   
        uint16_t       RX_flags;
        uint8_t        antenna_signal2;
        uint8_t        antenna;
}radiotap_header;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct Taggedparameter{
        uint8_t tagnum;
        uint8_t taglength;
        u_char  contents[50];
        Taggedparameter(uint8_t tagnum, uint8_t taglength,u_char* contents){
                this->tagnum=tagnum;
                this->taglength=taglength;
                memcpy(this->contents,contents,sizeof(u_char)*taglength);
        }
}Taggedparameter;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct ieeeheader{
        uint8_t        type_subtype; //8
        uint8_t        flag;    //00
        uint16_t       duration; //0
        Mac            dst_mac;
        Mac            src_mac;
        Mac            bssid;
        uint16_t       fragment_snum;
        uint16_t       fixed_parameters[6];
}ieeeheader;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct frame {
        struct radiotap_header rt_header;
        struct ieeeheader ie_header;
        uint8_t        tagged_parameter_area[150];
        frame(Mac ap, Mac st){
                this->rt_header.revision=0x00;
                this->rt_header.pad=0x00;
                this->rt_header.length=0x18;
                this->rt_header.present_flags=0xa000402e;
                this->rt_header.flags=0x00;
                this->rt_header.data_Rate=0x02;
                this->rt_header.channel_frequency=0x994;
                this->rt_header.channel_flags=0xa0;
                this->rt_header.antenna_signal=0xaf;
                this->rt_header.antenna_signal2=0xaf;
                this->rt_header.dummy=0x00;
                this->rt_header.RX_flags=0x00;
                this->rt_header.antenna=0x00;
                //
                this->ie_header.src_mac=ap;
                this->ie_header.bssid=ap;
                this->ie_header.dst_mac=st;
                this->ie_header.type_subtype=0x80;
                this->ie_header.flag=0x00;
                this->ie_header.duration=0x00;
                this->ie_header.fragment_snum=0x40ff;
                memset(this->ie_header.fixed_parameters,0,sizeof(uint32_t)*3);
                this->ie_header.fixed_parameters[4]=0x64;
                this->ie_header.fixed_parameters[5]=0x411;
        }
}frame;
#pragma pack(pop)
