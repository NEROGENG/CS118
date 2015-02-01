/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014,  Regents of the University of California
 *
 * This file is part of Simple BT.
 * See AUTHORS.md for complete list of Simple BT authors and contributors.
 *
 * NSL is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NSL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NSL, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * \author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SBT_CLIENT_HPP
#define SBT_CLIENT_HPP

#include "common.hpp"
#include <fstream>
#include "meta-info.hpp"
#include "http/http-request.hpp"
#include "http/url-encoding.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sstream>
#include "http/http-response.hpp"
#include "tracker-response.hpp"

 #include <netdb.h>
#include <arpa/inet.h>
#include <iostream>
 #include <cstring>
#include <stdlib.h>


#define INIT_BUFFER_SIZE 20

namespace sbt {


struct Params
{
  /* data */

  std::string info_hash;
  std::string peer_id;
  std::string port;
  std::string uploaded;
  std::string downloaded;
  std::string left;
  std::string event;

};


class Client
{
public:
  Client(const std::string& port, const std::string& torrent) : first_request(true)
  {

  	   std::ifstream torrent_file;
  	   torrent_file.open(torrent, std::ifstream::in);

  	   std::istream& is = torrent_file;    //wireCode will take 'is' as its parameter(refer to line 81)

  	   m_metaInfo.wireDecode(is);          //decode the torrent file and store the information in m_metaInfo
  	   torrent_file.close();

       std::string hash = url::encode(m_metaInfo.getHash()->get(), m_metaInfo.getHash()->size());     //convert the byte array into an escaped uri string
       
       m_parameters.info_hash = hash;                     //set the parameters
       m_parameters.peer_id = "ABCDEFGHIJKLMNOPQRST";
       // m_parameters.ip = getIP("localhost");
       m_parameters.port = port;
       m_parameters.uploaded = "0";
       m_parameters.downloaded = "0";
       m_parameters.left = "9000";
       m_parameters.event = "started";

       //std::cerr << m_parameters.ip << std::endl;

  }

  void send_http_request_and_receive_from_tracker()     //we integrated the sending and recieving part into one single function
  {


    std::string http_request_string;
    if (first_request)        //only when it's the first request do we need to include the event code 'started'
    {
    http_request_string = "GET " + 
                          m_metaInfo.getAnnounce() + 
                          "?info_hash=" + m_parameters.info_hash +
                          "&peer_id=" + m_parameters.peer_id +
                          "&port=" + m_parameters.port +
                          "&uploaded=" + m_parameters.uploaded +
                          "&downloaded=" + m_parameters.downloaded +
                          "&left=" + m_parameters.left +
                          "&event=" + m_parameters.event +
                          " HTTP/1.0\r\n" + 
                          m_metaInfo.getAnnounce() + 
                          "\r\n\r\n";
    }
    else
    {
    http_request_string = "GET " + 
                          m_metaInfo.getAnnounce() + 
                          "?info_hash=" + m_parameters.info_hash +
                          "&peer_id=" + m_parameters.peer_id +
                          "&port=" + m_parameters.port +
                          "&uploaded=" + m_parameters.uploaded +
                          "&downloaded=" + m_parameters.downloaded +
                          "&left=" + m_parameters.left +
                          " HTTP/1.0\r\n" + 
                          m_metaInfo.getAnnounce() + 
                          "\r\n\r\n";
    }

    m_req.parseRequest(http_request_string.c_str(), http_request_string.size());     //parse the http request and store the tokenized partitions into m_req
    char* buffer = new char[m_req.getTotalLength() + 1];
    m_req.formatRequest(buffer);                          //reform the request using the partitions achieved in line 134
    buffer[m_req.getTotalLength()] = '\0';

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);         //create a socket using TCP

    struct sockaddr_in serverAddr;
    //set the parameters of serverAddr
    std::string serverIP = getIP(m_req.getHost().c_str());    //get the host IP address
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());
    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));   //set NULL character
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(m_req.getPort());             //get the port number

    // connect to the server
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
      delete []buffer;
      return;
    }

    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    if (getsockname(sockfd, (struct sockaddr *)&clientAddr, &clientAddrLen) == -1) {
      delete []buffer;
      return;
    }


    if (send(sockfd, buffer, m_req.getTotalLength() + 1, 0) == -1) {
      delete []buffer;
      close(sockfd);
      return;
    }

    size_t received_bufsize = 0;                      //track the buffer size

    char* receiveBuf = new char[INIT_BUFFER_SIZE];    //dynamically allocate a buffer to continuously store the recieved response

    receiveBuf[0] = '\0';     //set NULL character

    char temp_buf1[INIT_BUFFER_SIZE];

    temp_buf1[0] = '\0';      //set NULL character

    int rtrn;

    while ((rtrn = recv(sockfd,temp_buf1,INIT_BUFFER_SIZE,0)) != 0)     //stay in the loop until all the response has been recieved
    {
      char* temp_buf2 = new char[received_bufsize+INIT_BUFFER_SIZE];
      memcpy(temp_buf2, receiveBuf, received_bufsize);                  //temp_buf2 = the old recieved buffer + the newly incoming buffer
      memcpy(temp_buf2+received_bufsize, temp_buf1, INIT_BUFFER_SIZE);
      received_bufsize += INIT_BUFFER_SIZE;
      delete []receiveBuf;
      receiveBuf = new char[received_bufsize];
      memcpy(receiveBuf, temp_buf2, received_bufsize);
      delete []temp_buf2;
      memset(temp_buf1, '\0', INIT_BUFFER_SIZE);    //set NULL character
     
    }

    if (receiveBuf[0] == '\0')    //all the response has been recieved
    {
      delete []receiveBuf;
      delete []buffer;
      close(sockfd);
      return;
    }

    //parseResponse returns a char pointer that points to the starting position of the body of http response, i.e. the starting position of actual tracker response.
    const char* bodyStartPos=m_HR.parseResponse(receiveBuf,received_bufsize);

    TrackerResponse m_TR;
    std::istringstream is(bodyStartPos);  //this way, 'is' can be passed as a paramater when we want to decode the tracker response in a bencoding dictionary (refer to line 212)

    bencoding::Dictionary dict;
    dict.wireDecode(is);
    m_TR.decode(dict);

    if (first_request)    //we only print out the ips and ports when it's the first request
    {
        for(unsigned i=0;i<m_TR.getPeers().size();i++)
          std::cout <<m_TR.getPeers().at(i).ip<<":"<<m_TR.getPeers().at(i).port<<std::endl;
    }

    sleep(m_TR.getInterval());

    close(sockfd);

    delete []receiveBuf;
    delete []buffer;

    first_request = false;    //from now on, it's no longer the first request
    return;
  }

  std::string getIP(std::string host)
  {
    struct addrinfo hints;
    struct addrinfo* res;

    // prepare hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    std::string IPstring;

    // get address

    int status = 0;
    if ((status = getaddrinfo(host.c_str(), NULL, &hints, &res)) != 0) {
      // std::cerr << "getaddrinfo: " << gai_strerror(status) << std::endl;
    }


    for(struct addrinfo* p = res; p != 0; p = p->ai_next)
    {
      // convert address to IPv4 address
      struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;

      // convert the IP to a string and print it:
      char ipstr[INET_ADDRSTRLEN] = {'\0'};
      inet_ntop(p->ai_family, &(ipv4->sin_addr), ipstr, sizeof(ipstr));

      IPstring = std::string(ipstr);

    }

    freeaddrinfo(res); // free the linked list

    return IPstring;
  }



private:

	MetaInfo m_metaInfo;

  HttpRequest m_req;      //parse and store the http request

  struct Params m_parameters;

  HttpResponse m_HR;      //parse and store the http response

  bool first_request;     //denote whether this is the first http request sent

};

} // namespace sbt

#endif // SBT_CLIENT_HPP
