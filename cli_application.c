/*
############################################################################################
# File:             cli_application.c
# Author:           Smeet Raj
# Date:             18th Feb 2024
# Description:      The CLI application allows users to interact with the packet analyzer. 
#                   It provides commands to start, stop, and exit the packet capture process.
# 
# Copyright (c) 2024 Smeet Raj
# All rights reserved.
############################################################################################
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

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

    // Connect to the packet analyzer
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    {
        perror("connect");
        return 1;
    }

    // Interactive CLI
    char cmd[10];
    while (1) 
    {
        printf("Enter command: ");
        scanf("%s", cmd);

        // Send command to the packet analyzer
        if (send(sockfd, cmd, strlen(cmd), 0) < 0) 
        {
            perror("send");
            break;
        }

        // Toggle start/stop on 'S' key
        if (strcmp(cmd, "S") == 0) 
        {
            printf("Toggle start/stop\n");
            continue;
        }

        // Exit on 'exit' command
        if (strcmp(cmd, "exit") == 0) 
        {
            printf("Exiting...\n");
            break;
        }
    }

    // Close the socket
    close(sockfd);

    return 0;
}
