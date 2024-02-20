/*
############################################################################################
# File:             packet_analyzer.c
# Author:           Smeet Raj
# Date:             17th Feb 2024
# Description:      The packet analyzer captures TCP packets, analyzes them, 
#                   and calculates various parameters such as throughput, retransmitted packets, and packet loss rate.
# 
# Copyright (c) 2024 Smeet Raj
# All rights reserved.
############################################################################################
*/

//###############################################################################
//  INCLUDES
//###############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


//###############################################################################
//  MACROS
//###############################################################################


#define MAX_PACKETS_TO_DISPLAY 10
#define OUTPUT_FILE "captured_packets.txt"

//###############################################################################
//  FUNCTION PROTOTYPES
//###############################################################################
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);


//###############################################################################
//  STATIC VARIABLES
//###############################################################################
static int      packet_count = 0;
static time_t   start_time;
static uint32_t last_seq_num = 0;
static int      retransmitted_packets = 0;
static int      transmitted_packets = 0;
static int      received_packets = 0;


//###############################################################################
//  MAIN
//###############################################################################
int main(int argc, char *argv[]) 
{
    // Create a Unix domain socket
    int sockfd;
    struct sockaddr_un serv_addr;

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) 
    {
        perror("socket");
        return 1;
    }

    // Set server address
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, SOCK_PATH, sizeof(serv_addr.sun_path) - 1);

    // Bind the socket
    unlink(SOCK_PATH); // Remove any existing socket with the same name
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    {
        perror("bind");
        return 1;
    }

    // Listen for connections
    if (listen(sockfd, 1) < 0) 
    {
        perror("listen");
        return 1;
    }

    // Accept connections and handle commands
    while (1) 
    {
        int newsockfd, clilen;
        struct sockaddr_un cli_addr;
        clilen = sizeof(cli_addr);
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) 
        {
            perror("accept");
            return 1;
        }

        // Receive command from CLI application
        char cmd[10];
        ssize_t bytes_read = recv(newsockfd, cmd, sizeof(cmd), 0);
        if (bytes_read > 0) 
        {
            cmd[bytes_read] = '\0';
            if (strcmp(cmd, "start") == 0) 
            {
                // Open the network interface for packet capture
                pcap_t *handle;
                char errbuf[PCAP_ERRBUF_SIZE];
                handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
                if (handle == NULL) 
                {
                    fprintf(stderr, "Couldn't open device: %s\n", errbuf);
                    return 1;
                }

                // Start packet capture
                packet_count = 0;
                start_time = time(NULL);
                pcap_loop(handle, 0, packet_handler, NULL);
            } 
            else if (strcmp(cmd, "stop") == 0) 
            {
                // Stop packet capture
                pcap_breakloop(handle);
            }
        }

        close(newsockfd);
    }

    return 0;
}


//###############################################################################
//  FUNCTION DEFINITIONS
//###############################################################################

/**
 * @brief Callback function to process packets
 * @param user_data Parameter description
 * @param pkthdr Parameter description
 * @param packet Parameter description
 * @return Return description
**/
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;

    // Parse Ethernet header
    eth_header = (struct ether_header *) packet;

    // Check if packet is IP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) 
    {
        // Parse IP header
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        // Check if packet is TCP
        if (ip_header->ip_p == IPPROTO_TCP) 
        {
            // Increment packet count
            packet_count++;

            // Calculate throughput
            time_t current_time = time(NULL);
            double elapsed_time = difftime(current_time, start_time);
            double throughput = (double)(packet_count * pkthdr->len * 8) / (1000000 * elapsed_time); // in Mbps

            // Update transmitted packets count
            transmitted_packets++;

            // Check if the packet is a retransmission
            if (tcp_header->th_seq == last_seq_num) 
            {
                retransmitted_packets++;
            } 
            else 
            {
                last_seq_num = tcp_header->th_seq;
            }

            // Display packet information
            printf("Packet %d - Throughput: %.2f Mbps, Retransmitted Packets: %d\n", packet_count, throughput, retransmitted_packets);

            // Save the packet to a text file
            FILE *output_file = fopen(OUTPUT_FILE, "a");
            if (output_file) {
                fprintf(output_file, "Packet %d - Length: %d bytes\n", packet_count, pkthdr->len);
                fclose(output_file);
            }
        }
    }
}
