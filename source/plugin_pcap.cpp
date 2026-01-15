#include "plugin_pcap.hpp"
#include <cstring>
#include <pcap.h>
#include <hex/helpers/logger.hpp>
#include <hex/ui/imgui_imhex_extensions.h>
#include <hex/ui/popup.hpp>

void PcapProvider::readRaw(u64 offset, void *buffer, size_t size) {
    if (offset > (this->getActualSize() - size) || buffer == nullptr || size == 0){
        hex::log::warn("Can't read {} bytes at {}. Only {} totale bytes. buffer_ptr={}\n", 
            size, offset, this->getActualSize(), buffer);
        return;
    }

    std::memcpy(buffer, &(m_data[offset]), size);
}

std::string PcapProvider::getName() const {
    return wolv::util::toUTF8String(this->m_path.filename());
}

bool PcapProvider::handleFilePicker() {
    return hex::fs::openFileBrowser(hex::fs::DialogMode::Open, {{ "Packet Capture", "pcap"}, { "Packet Capture", "pcapng"}}, [this](const auto &path) {
         this->m_path = path;
    });
}

bool PcapProvider::open() {
    if (!std::fs::exists(this->m_path)) {
        this->setErrorMessage(hex::format("Error opening {} ({})", this->m_path.string(), ::strerror(ENOENT)));
        return false;
    }
    if (!loadPacketList()) return false;

    m_page = 1;
    m_selected_packets[0] = m_packet_descs.begin()->first;
    return loadPackets();
}

std::pair<hex::Region, bool> PcapProvider::getRegionValidity(u64 address) const {
    address -= this->getBaseAddress();

    if (address < this->getActualSize())
        return { hex::Region { this->getBaseAddress() + address, this->getActualSize() - address }, true };
    else
        return { hex::Region::Invalid(), false };
}

void PcapProvider::drawInterface() {
    ImGuiExt::Header(this->m_path.string().c_str(), true);
    
    // Berkeley Packet Filter section
    ImGuiExt::Header("Berkeley Packet Filter", true);
    static char bpf_str[256];
    static bool valid_filter = true;
    static std::string last_validated_filter;
    static float validation_timer = 0.0f;
    static const float VALIDATION_DELAY = 0.5f; // Wait 500ms after last keystroke
    
    bool filter_changed = false;
    if (ImGui::InputText("BPF Filter", bpf_str, IM_ARRAYSIZE(bpf_str), ImGuiInputTextFlags_EnterReturnsTrue)) {
        if (valid_filter) {
            this->m_bpf = bpf_str;
            hex::log::warn("bpf reopen");
            this->open();
        }
        filter_changed = true;
    } 
    
    // Debounced validation - only validate after user stops typing
    if (ImGui::IsItemEdited()) {
        filter_changed = true;
        validation_timer = VALIDATION_DELAY;
    }
    
    // Update timer and validate when timer expires
    if (validation_timer > 0.0f) {
        validation_timer -= ImGui::GetIO().DeltaTime;
        if (validation_timer <= 0.0f) {
            std::string current_filter(bpf_str);
            if (current_filter != last_validated_filter) {
                valid_filter = isBpfValid(bpf_str);
                last_validated_filter = current_filter;
            }
        }
    }
    
    ImGui::SameLine();
    ImGui::PushItemFlag(ImGuiItemFlags_NoTabStop, true);
    // Show different colors: green=valid, red=invalid, yellow=validating
    ImVec4 color = valid_filter ? ImVec4(0,0.5f,0,1) : ImVec4(0.5f,0,0,1);
    if (validation_timer > 0.0f) color = ImVec4(0.5f,0.5f,0,1); // Yellow while waiting
    ImGui::ColorButton("##Valid", color, ImGuiColorEditFlags_NoTooltip);
    ImGui::PopItemFlag();
    // Packets section
    ImGuiExt::Header("Packets", true);
    
    // Make the packet list resizable
    static float packet_list_height = 300.0f;
    if (ImGui::BeginChild("PacketList", ImVec2(0, packet_list_height), true, ImGuiWindowFlags_HorizontalScrollbar)) {
        u_int idx = 0;
        bool updated = false;
        for( std::map<u_int, std::string>::iterator iter = m_packet_descs.begin(); iter != m_packet_descs.end(); ++iter )
        {
            const bool selected = this->m_selected_packets.count(idx);
            if ((idx / PCAP_PAGE_SIZE) == (unsigned int)(m_page - 1)) {
                if (ImGui::Selectable(iter->second.c_str(), selected)) {
                    if (ImGui::IsKeyDown(ImGuiMod_Ctrl)) {  //multiselect/deselect
                        if (selected) m_selected_packets.erase(idx);
                        else m_selected_packets[idx] = iter->first;
                    }
                    else {
                        m_selected_packets.clear();
                        m_selected_packets[idx] = iter->first;
                    }
                    updated = true;
                }
            }
            idx++;
        }
        if (updated) {
            this->loadPackets();
        }
    }
    ImGui::EndChild();
    
    // Resizer for packet list
    ImGui::Button("##PacketListResizer", ImVec2(-1, 8));
    if (ImGui::IsItemActive()) {
        packet_list_height += ImGui::GetIO().MouseDelta.y;
        if (packet_list_height < 100) packet_list_height = 100;
        if (packet_list_height > 600) packet_list_height = 600;
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
    }
    
    // Pagination controls
    int v_max = 1 + (m_packet_descs.size() / PCAP_PAGE_SIZE);
    if (ImGui::ArrowButton("page_prev", ImGuiDir_Left)) {
        if (m_page>1) m_page--;
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100);
    ImGui::SliderInt("Page", &m_page, 1, v_max, "%d", ImGuiSliderFlags_AlwaysClamp);
    ImGui::SameLine();
    if (ImGui::ArrowButton("page_next", ImGuiDir_Right)) {
        if (m_page < v_max) m_page++;
    }
    
    // Show selection info
    ImGui::SameLine();
    ImGui::Text("(%d packets selected)", (int)m_selected_packets.size());
}

bool PcapProvider::isBpfValid(char* bpf) {
    // Quick validation for empty or common invalid cases
    if (!bpf || strlen(bpf) == 0) {
        return true; // Empty filter is valid
    }
    
    // Cache the pcap handle to avoid repeated allocation
    static pcap_t *cached_fp = nullptr;
    static std::string last_valid_filter;
    static bool last_result = true;
    
    // Check cache first
    std::string current_filter(bpf);
    if (current_filter == last_valid_filter) {
        return last_result;
    }
    
    // Initialize cached handle if needed
    if (!cached_fp) {
        cached_fp = pcap_open_dead(DLT_EN10MB, 65535);
        if (!cached_fp) {
            return false;
        }
    }
    
    // Validate the filter
    struct bpf_program filter;
    bool ret = false;
    if (pcap_compile(cached_fp, &filter, bpf, 0, PCAP_NETMASK_UNKNOWN) == 0) {
        ret = true;
        pcap_freecode(&filter);
    }
    
    // Update cache
    last_valid_filter = current_filter;
    last_result = ret;
    
    return ret;
}

bool PcapProvider::loadPacketList() {
    pcap_t *fp;
    unsigned int pkt_idx=0;
    const u_char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    struct pcap_pkthdr *header;   
    char line[256];
    int ret;

    fp = pcap_open_offline(this->m_path.string().c_str(), errbuf);
    if (fp == NULL) {
        this->setErrorMessage(hex::format("Failed to open {} ({})", this->m_path.string(), errbuf));
        return false;
    }

    m_packet_descs.clear();
    m_selected_packets.clear();
    if (m_bpf[0]) {
        struct bpf_program filter;
        if (pcap_compile(fp, &filter, m_bpf.c_str(), 0, PCAP_NETMASK_UNKNOWN) == 0) {
            if (pcap_setfilter(fp, &filter) == -1) {
                hex::log::warn(hex::format("Invalid filter: {}", pcap_geterr(fp)));
            }
            pcap_freecode(&filter);
        }
        else {
            hex::log::warn(hex::format("Invalid filter: {}", pcap_geterr(fp)));
        }
    }

    while ((ret = pcap_next_ex(fp, &header, &packet)) == 1) { 
        const struct ethernet_hdr* ethernetHeader;
        const struct ip_hdr* ipHeader;
        const struct tcp_hdr* tcpHeader;
        const struct udp_hdr* udpHeader;
        u_int sourcePort, destPort;
        u_int offset;
        u_int data_len = 0;
        pkt_idx++;
        
        ethernetHeader = (struct ethernet_hdr*)packet;
        offset = sizeof(struct ethernet_hdr);
        if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
            ipHeader = (struct ip_hdr*)(packet + offset);
            offset += ipHeader->ip_hl * 4;
            inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
            if (ipHeader->ip_p == IPPROTO_TCP) {
                tcpHeader = (struct tcp_hdr*)(packet + offset);
                offset += tcpHeader->th_off * 4;
                sourcePort = ntohs(tcpHeader->th_sport);
                destPort = ntohs(tcpHeader->th_dport);
                data_len = header->len - offset;
                snprintf(line, sizeof(line), "#%-4d %15s:%-5d -> %15s:%-5d TCP %d bytes", 
                    pkt_idx, sourceIP, sourcePort, destIP, destPort, data_len);
            } else if (ipHeader->ip_p == IPPROTO_UDP) {
                udpHeader = (struct udp_hdr*)(packet + offset);
                offset += sizeof(struct udp_hdr);
                sourcePort = ntohs(udpHeader->uh_sport);
                destPort = ntohs(udpHeader->uh_dport);
                data_len = header->len - offset;
                snprintf(line, sizeof(line), "#%-4d %15s:%-5d -> %15s:%-5d UDP %d bytes", 
                    pkt_idx, sourceIP, sourcePort, destIP, destPort, data_len);
            } 
            else {
                data_len = header->len - offset;
                snprintf(line, sizeof(line), "#%-4d %16s -> %16s IP %d bytes", 
                    pkt_idx, sourceIP, destIP, data_len);
            }
        }
        else {
            data_len = header->len - offset;
            snprintf(line, sizeof(line), "#%-4d %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x %d bytes", 
                    pkt_idx, ethernetHeader->ether_shost[0], ethernetHeader->ether_shost[1], ethernetHeader->ether_shost[2], 
                    ethernetHeader->ether_shost[3], ethernetHeader->ether_shost[4], ethernetHeader->ether_shost[5],
                    ethernetHeader->ether_dhost[0], ethernetHeader->ether_dhost[1], ethernetHeader->ether_dhost[2], 
                    ethernetHeader->ether_dhost[3], ethernetHeader->ether_dhost[4], ethernetHeader->ether_dhost[5], data_len);
        }
        
        if (data_len) {
            m_packet_descs[pkt_idx] = std::string(line);
        }
    }
    pcap_close(fp);
    if (ret == PCAP_ERROR) {
        this->setErrorMessage(hex::format("Error reading {} ({})", this->m_path.string(), pcap_geterr(fp)));
        return false;
    }
    return true;
}  

bool PcapProvider::loadPackets() {
    pcap_t *fp;
    unsigned int pkt_idx=0;
    const u_char *packet;
    struct pcap_pkthdr *header;   
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret = 0;

    fp = pcap_open_offline(this->m_path.string().c_str(), errbuf);
    if (fp == NULL) {
        this->setErrorMessage(hex::format("Failed to open {} ({})", this->m_path.string(), errbuf));
        return false;
    }

    if (m_bpf[0]) {
        struct bpf_program filter;
        if (pcap_compile(fp, &filter, m_bpf.c_str(), 0, PCAP_NETMASK_UNKNOWN) == 0) {
            if (pcap_setfilter(fp, &filter) == -1) {
                hex::log::warn(hex::format("Invalid filter: {}", pcap_geterr(fp)));
            }
            pcap_freecode(&filter);
        }
        else {
            hex::log::warn(hex::format("Invalid filter: {}", pcap_geterr(fp)));
        }
    }

    m_data.clear();
    for( std::map<u_int, u_int>::iterator iter = m_selected_packets.begin(); iter != m_selected_packets.end(); ++iter ) {
        while ((ret = pcap_next_ex(fp, &header, &packet)) == 1) { 
            if (++pkt_idx == iter->second) {
                const struct ethernet_hdr* ethernetHeader;
                const struct ip_hdr* ipHeader;
                const struct tcp_hdr* tcpHeader;
                //const struct udphdr* udpHeader;
                u_int offset;
                u_int data_len;
                u_int data_pre_len;
                
                ethernetHeader = (struct ethernet_hdr*)packet;
                offset = sizeof(struct ethernet_hdr);
                if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
                    ipHeader = (struct ip_hdr*)(packet + offset);
                    offset += ipHeader->ip_hl * 4;
                    if (ipHeader->ip_p == IPPROTO_TCP) {
                        tcpHeader = (struct tcp_hdr*)(packet + offset);
                        offset += tcpHeader->th_off * 4;
                        data_len = header->len - offset;
                        data_pre_len = this->m_data.size();
                        this->m_data.resize(data_pre_len + data_len);
                        std::memcpy(&this->m_data[data_pre_len], packet + offset, data_len);
                    } else if (ipHeader->ip_p == IPPROTO_UDP) {
                        //udpHeader = (struct udp_hdr*)(packet + offset);
                        offset += sizeof(struct udp_hdr);
                        data_len = header->len - offset;
                        data_pre_len = this->m_data.size();
                        this->m_data.resize(data_pre_len + data_len);
                        std::memcpy(&this->m_data[data_pre_len], packet + offset, data_len);
                    } 
                }
                else {
                    data_len = header->len - offset;
                    data_pre_len = this->m_data.size();
                    this->m_data.resize(data_pre_len + data_len);
                    std::memcpy(&this->m_data[data_pre_len], packet + offset, data_len);
                }
                break;
            }
        } 
    }
    
    if (ret == -1) { //error reading packets
        this->setErrorMessage(hex::format("Error reading {} ({})", this->m_path.string(), pcap_geterr(fp)));
    }

    pcap_close(fp);
    return ret == 1;
}

IMHEX_PLUGIN_SETUP("Pcap Provider", "Dragos", "Plugin for reading pcap files") {
    hex::ContentRegistry::Provider::add<PcapProvider>(true);
}

        