#if defined(OS_WINDOWS)
    #include <winsock2.h>
    #include <windows.h>
#endif
#include <hex/plugin.hpp>
#include <hex/providers/provider.hpp>
#include <hex/api/content_registry.hpp>
#include <pcap.h>
#include <map>



/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct ethernet_hdr {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif


/* IP header */
struct ip_hdr {
#if IS_BIG_ENDIAN
    u_char  ip_v:4,         /* version */
            ip_hl:4;        /* header length */
#else 
    u_char  ip_hl:4,        /* header length */
            ip_v:4;         /* version */
#endif
    u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct tcp_hdr {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
#if IS_BIG_ENDIAN 
    u_char th_off:4;                /* data offset */
    u_char th_x2:4;                /* (unused) */
#else
    u_char th_x2:4;                /* (unused) */
    u_char th_off:4;                /* data offset */
#  endif
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};


/* UDP header */
struct udp_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};


class PcapProvider : public hex::prv::Provider {
public:
    PcapProvider() : hex::prv::Provider() {};
    ~PcapProvider() override = default;

    [[nodiscard]] bool isAvailable() const override {return true;}
    [[nodiscard]] bool isReadable() const override {return true;}
    [[nodiscard]] bool isWritable() const override {return false;}
    [[nodiscard]] bool isResizable() const override {return false;}
    [[nodiscard]] bool isSavable() const override {return false;}

    void readRaw(u64 offset, void *buffer, size_t size) override;
    void writeRaw(u64 offset, const void *buffer, size_t size) override { hex::unused(offset, buffer, size);}
    [[nodiscard]] size_t getActualSize() const override {return this->m_data.size();}

    [[nodiscard]] std::string getName() const override;
    [[nodiscard]] std::vector<Description> getDataDescription() const override { return { }; };

    [[nodiscard]] bool hasFilePicker() const override { return true; }
    [[nodiscard]] bool handleFilePicker() override;

    [[nodiscard]] bool open() override;
    void close() override {};

    std::pair<hex::Region, bool> getRegionValidity(u64 address) const override;

    void loadSettings(const nlohmann::json &settings) override { hex::unused(settings);}
    [[nodiscard]] nlohmann::json storeSettings(nlohmann::json settings) const override { return settings; }

    [[nodiscard]] std::string getTypeName() const override {return "Pcap Provider"; }

    [[nodiscard]] virtual bool hasInterface() const override {return true;};
    void drawInterface() override;

protected:
    bool static isBpfValid(char* bpf);
    //These two functions have a lot of duplicate code yet different enough to be convoluted if combined
    bool loadPacketList();
    bool loadPackets();   
    
    std::string m_bpf;
    std::fs::path m_path;
    std::vector<u8> m_data;
    std::map<u_int, std::string> m_packet_descs;
    std::map<u_int, u_int> m_selected_packets;
};