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

#include "client.hpp"
#include "tracker-request-param.hpp"
#include "tracker-response.hpp"
#include "http/http-request.hpp"
#include "http/http-response.hpp"
#include "msg/handshake.hpp"
#include "util/buffer-stream.hpp"
#include "util/hash.hpp"
#include <sstream>
#include <fstream>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>
#include <ifaddrs.h>



#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <cstring>
#include <algorithm>


namespace sbt {

Client::Client(const std::string& port, const std::string& torrent)
  : m_interval(3600)
  , m_isFirstReq(true)
  , m_isFirstRes(true)
  , m_downloaded(0)
  , m_uploaded(0)
  , m_isComplete(false)
  , m_left(0)
{
  srand(time(NULL));
 
  m_clientPort = boost::lexical_cast<uint16_t>(port);
 
  m_myIP = getMyIP();

 
  loadMetaInfo(torrent);
 
  m_numPieces = ceil((double)m_metaInfo.getLength()/(double)m_metaInfo.getPieceLength());
  // std::cout << "Number of Pieces: " << m_numPieces << std::endl;
 
  checkFileOrCreate();

 
  run();
}

void
Client::checkFileOrCreate() 
{ 
  if (checkFile(m_metaInfo.getName()))
    ;
    //std::cout << m_metaInfo.getName() << " exists!" << std::endl;
  else {
    //std::cout << m_metaInfo.getName() << " does not exist! Let's create one!" << std::endl;

    std::ofstream ofs(m_metaInfo.getName(), std::ios::binary | std::ios::out);
    ofs.seekp(m_metaInfo.getLength() - 1);
    ofs.write("", 1);
    std::vector<uint8_t> v(ceil(m_numPieces/8.0), '\0');
    m_bitfield = v;
  }

  for (int i = 0; i < m_numPieces - 1; i++) {
    if (hasPiece(m_bitfield, i))
      m_left += m_metaInfo.getPieceLength();
  }
  if (hasPiece(m_bitfield, m_numPieces - 1))
    m_left += m_metaInfo.getLength() - m_metaInfo.getPieceLength() * (m_numPieces - 1);
  m_left = m_metaInfo.getLength() - m_left;

  m_isComplete = false;
 
}
 
void
Client::loadMetaInfo(const std::string& torrent)
{
  std::ifstream is(torrent);
  m_metaInfo.wireDecode(is);
 
  std::string announce = m_metaInfo.getAnnounce();
  std::string url;
  std::string defaultPort;
  if (announce.substr(0, 5) == "https") {
    url = announce.substr(8);
    defaultPort = "443";
  }
  else if (announce.substr(0, 4) == "http") {
    url = announce.substr(7);
    defaultPort = "80";
  }
  else
    throw Error("Wrong tracker url, wrong scheme");
 
  size_t slashPos = url.find('/');
  if (slashPos == std::string::npos) {
    throw Error("Wrong tracker url, no file");
  }
  m_trackerFile = url.substr(slashPos);
 
  std::string host = url.substr(0, slashPos);
 
  size_t colonPos = host.find(':');
  if (colonPos == std::string::npos) {
    m_trackerHost = host;
    m_trackerPort = defaultPort;
  }
  else {
    m_trackerHost = host.substr(0, colonPos);
    m_trackerPort = host.substr(colonPos + 1);
  }
}
 
bool
Client::checkFile(const std::string& filename) {
  std::fstream f(filename, std::fstream::in | std::fstream::out | std::fstream::ate);
 
  if (!f.good() || f.tellg() > m_metaInfo.getLength()) {
    f.close();
    return false;
  }
  else if (f.tellg() < m_metaInfo.getLength()) {
    std::cout<< f.tellg() << " against " << m_metaInfo.getLength() << std::endl;
    f.seekp(m_metaInfo.getLength() - 1);
    f.write("", 1);
    std::cout<< f.tellg() << " against " << m_metaInfo.getLength() << std::endl;
  }
 
  f.seekg(0, f.beg);
  std::vector<uint8_t> bitfield(ceil(m_numPieces/8.0), '\0');
  // std::cout << bitfield.size() << " bytes" << std::endl;
 
  std::vector<uint8_t> v = m_metaInfo.getPieces();
  int pieceLength = m_metaInfo.getPieceLength();
 
  for (int i = 0; i < m_numPieces; i++) {
    std::string temp = std::string(v.begin() + i * 20, v.begin() + (i + 1) * 20);  // #HARD#
    // std::cout << temp << "@  " << i << "  @" << std::endl;
    f.seekg(i * pieceLength, f.beg);
    char* buf = new char[pieceLength + 1];
    memset(buf, '\0', pieceLength + 1);
    f.readsome(buf, pieceLength);
 
    if (validatePiece(std::string(buf), temp))
      bitfield[i / 8] |= 1 << (i % 8);
 
    delete buf;
    // std::cout << util::sha1(std::string(buf)) << "@  " << i << "  @" << std::endl;
  }
   
  m_bitfield = bitfield;
  // std::cout << (int)m_bitfield[0] << (int)m_bitfield[1] << (int)m_bitfield[2] << std::endl;
 
  f.close();
  return true;
}

void
Client::run()
{


  //++++++++++++++++++++++ LISTEN ++++++++++++++++++++++++

  int maxSockfd = 0;
  fd_set readFds;
  fd_set tmpFds;
  FD_ZERO(&readFds);
  FD_ZERO(&tmpFds);

  // create a socket using TCP IP
  int sockfd_listen = socket(AF_INET, SOCK_STREAM, 0); // This is listenning socketID
  maxSockfd = sockfd_listen;

  // put the socket in the socket set
  FD_SET(sockfd_listen, &readFds);

  // allow others to reuse the address
  int yes = 1;
  if (setsockopt(sockfd_listen, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    perror("setsockopt");
    return ;
  }

  // bind address to socket
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(m_clientPort);     // short, network byte order
  addr.sin_addr.s_addr = inet_addr(getMyIP().c_str());
  memset(addr.sin_zero, '\0', sizeof(addr.sin_zero));

  if (bind(sockfd_listen, (struct sockaddr*)&addr, sizeof(addr)) == -1) 
  {
    perror("bind");
    return ;
  }

  // set the socket in listen status
  if (listen(sockfd_listen, 10) == -1)  // #Q#
  {
    perror("listen");
    return ;
  }

  //++++++++++++++++++++++ LISTEN ++++++++++++++++++++++++



  //++++++++++++++++++++++ SEND REQUEST TO TRACKER ++++++++++++++++++++++++++++++
  connectTracker();
  sendTrackerRequest();
  FD_SET(m_trackerSock, &readFds);
  tmpFds = readFds;
  m_isFirstReq = false;
  if (maxSockfd < m_trackerSock)
        maxSockfd = m_trackerSock;

  //++++++++++++++++++++++ SEND REQUEST TO TRACKER ++++++++++++++++++++++++++++++


  // initialize timer
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 0;

  struct timeval old_tv;

  old_tv.tv_sec = 0;
  old_tv.tv_usec = 0;

  struct timeval new_tv;
  new_tv.tv_sec = 0;
  new_tv.tv_usec = 0;


  while (true) 
  {

    tv.tv_sec  = new_tv.tv_sec - old_tv.tv_sec;
    tv.tv_sec  = m_interval - tv.tv_sec;

    int rtrn = select(maxSockfd + 1, &readFds, NULL, NULL, &tv);

    if (rtrn == -1) 
    {
      perror("select");
      return;
    }
    else if (rtrn == 0)
    {


        connectTracker();
        sendTrackerRequest();
        readFds = tmpFds;
        FD_SET(m_trackerSock, &readFds);
        if (maxSockfd < m_trackerSock)
            maxSockfd = m_trackerSock;

        //readFds = tmpFds;

    }

    gettimeofday(&old_tv, NULL);

    for(int fd = 0; fd <= maxSockfd; fd++) 
    {

      //readFds = tmpFds;
      
      // get one socket for reading
      if (FD_ISSET(fd, &readFds)) 
      {

        if (fd == sockfd_listen) // this is the listen socket
        { 
          struct sockaddr_in clientAddr;
          socklen_t clientAddrSize;
          int clientSockfd = accept(fd, (struct sockaddr*)&clientAddr, &clientAddrSize);

          if (clientSockfd == -1) 
          {
            perror("accept");
            return ;
          }

          //++++++++++++++++++++++++++ HANDSHAKE +++++++++++++++++++++++++++++++

          Buffer received_handshake;

          char buf[20] = {0};
          memset(buf, '\0', 20);
          int temp_received = 0;
          int pos = 0;


          while (received_handshake.size() < 68)
          {

  
              temp_received = recv(clientSockfd , buf, 20, 0);

              if (temp_received == -1)
              {
                  perror("recev");
                  return ;
              }

              received_handshake.insert(received_handshake.begin()+pos, buf, buf+temp_received);

              pos += temp_received;

          }

          ConstBufferPtr handshake_CBP (new const Buffer(received_handshake.begin(), received_handshake.end()));
            
          sbt::msg::HandShake hd1;

          hd1.decode(handshake_CBP);

          if(std::equal(hd1.getInfoHash()->begin(), hd1.getInfoHash()->end(),m_metaInfo.getHash()->begin()))   //check info_hash
          {


              sbt::msg::HandShake hd2(m_metaInfo.getHash(),"SIMPLEBT.TEST.PEERID");
              ConstBufferPtr hdContent=hd2.encode();

              send(clientSockfd, hdContent->buf(), hdContent->size(), 0);

               // update maxSockfd
              if (maxSockfd < clientSockfd)
                  maxSockfd = clientSockfd;
              // add the socket into the socket set
              FD_SET(clientSockfd, &readFds);

              m_listen_list.push_back(clientSockfd);
              m_connectionlist.insert(std::pair<std::string, int>(hd1.getPeerId(), clientSockfd));
              m_inverseList.insert(std::pair<int,    std::string>(clientSockfd, hd1.getPeerId()));

          }
          else
          {

              close(clientSockfd);
              std::cout << "Info_hash not matched, handshake failed!" << std::endl;
          }

          //++++++++++++++++++++++++++ HANDSHAKE +++++++++++++++++++++++++++++++


        }
        else if (fd == m_trackerSock)
        { 

          good_response = true;

          TrackerResponse trackerResponse = recvTrackerResponse(good_response);

          m_interval = trackerResponse.getInterval();

          if (good_response)
          {
            m_peerlist = trackerResponse.getPeers();

            for (const auto& peer : m_peerlist) 
            {

              int peer_socket = socket(AF_INET, SOCK_STREAM, 0);

              struct sockaddr_in clientAddr;
              socklen_t clientAddrLen = sizeof(clientAddr);
              if (getsockname(peer_socket, (struct sockaddr *)&clientAddr, &clientAddrLen) == -1) 
              {
                  perror("getsockname");
                  return ;
              }

              char client_ipstr[INET_ADDRSTRLEN] = {'\0'};
              inet_ntop(clientAddr.sin_family, &clientAddr.sin_addr, client_ipstr, sizeof(client_ipstr));


              struct sockaddr_in serverAddr;
              serverAddr.sin_family = AF_INET;
              serverAddr.sin_port = htons(peer.port);     // short, network byte order
              serverAddr.sin_addr.s_addr = inet_addr(peer.ip.c_str());
              memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));

              
              if (getMyIP() != peer.ip || m_clientPort != peer.port)
              {


                      if (m_connectionlist.find(peer.peerId) == m_connectionlist.end())
                      {


                          if (connect(peer_socket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) 
                          {
                            perror("connect");
                            return ;
                          }
                      }

                      // ++++++++++++++++++ HANDSHAKE +++++++++++++++++++++++
                   
                      sbt::msg::HandShake hd1(m_metaInfo.getHash(),"SIMPLEBT.TEST.PEERID");
                      ConstBufferPtr hdContent=hd1.encode();

                      send(peer_socket, hdContent->buf(), hdContent->size(), 0);

                      Buffer received_handshake;

                      char buf[20] = {0};
                      memset(buf, '\0', 20);
                      int temp_received = 0;
                      int pos = 0;

                      while (received_handshake.size() < 68)
                      {
                          temp_received = recv(peer_socket, buf, 20, 0);

                          if (temp_received == -1)
                          {
                              perror("recev");
                              return ;
                          }

                          //std::cout << received_handshake.size() << std::endl;


                          received_handshake.insert(received_handshake.begin()+pos, buf, buf+temp_received);

                          pos += temp_received;
                      }


                      //auto handshake_CBP = std::make_shared<ConstBufferPtr>(received_handshake, received_handshake->size());
              

                      sbt::msg::HandShake hd2;

                      ConstBufferPtr handshake_CBP (new const Buffer(received_handshake.begin(), received_handshake.end()));

                      hd2.decode(handshake_CBP);

                      if(std::equal(hd2.getInfoHash()->begin(), hd2.getInfoHash()->end(),m_metaInfo.getHash()->begin()))   //check info_hash
                      {


                      // ++++++++++++++++++ HANDSHAKE +++++++++++++++++++++++


                      m_connectionlist.insert(std::pair<std::string, int>(peer.peerId, peer_socket));
                      m_inverseList.insert(std::pair<int,    std::string>(peer_socket, peer.peerId));

                      // ++++++++++++++++++ BITFIELD ++++++++++++++++++++++++

                      ConstBufferPtr bitFieldSend(new const Buffer(m_bitfield.begin(),m_bitfield.end()));
                      sbt::msg::Bitfield btf(bitFieldSend);
                      ConstBufferPtr BF = btf.encode();
                      
                      send(peer_socket, BF->buf(), BF->size(), 0);   //send its own bitfield

                      // ++++++++++++++++++ BITFIELD ++++++++++++++++++++++++

                      // update maxSockfd
                      if (maxSockfd < peer_socket)
                        maxSockfd = peer_socket;
                      // add the socket into the socket set
                      FD_SET(peer_socket, &readFds);


                      }
                      else
                      {

                          close(peer_socket);
                          std::cout << "Info_hash not matched, handshake failed!" << std::endl;
                      }

                  

               }


             }

            }

          close(m_trackerSock);

          //remove the socket from the socket set
          FD_CLR(m_trackerSock, &readFds);
        }
      
        else
        {

          Buffer received_buf;  
  
          char buf1[4] = {0};
          memset(buf1, '\0', 4);
          int temp_received1 = 0;
          int pos1 = 0;       
       
          while (received_buf.size() < 4)
          {
              temp_received1 = recv(fd , buf1, 4, 0);
       
              if (temp_received1 == -1)
              {
                  perror("recev");
                  return ;
              }

              //std::cout << buf1 << std::endl;

              received_buf.insert(received_buf.begin()+pos1, buf1, buf1+temp_received1);
       
              pos1 += temp_received1;
          }

          unsigned received_length_int = (received_buf[0] << 24) | (received_buf[1] << 16) | (received_buf[2] << 8) | received_buf[3];

          //std::cout << received_length_int << std::endl;
       
          char buf2[4] = {0};
          memset(buf2, '\0', 4);
          int temp_received2 = 0;
          int pos2 = 4;
       
          while (received_buf.size() < received_length_int + 4)
          {
              temp_received2 = recv(fd , buf2, 4, 0);
       
              if (temp_received2 == -1)
              {
                  perror("recev");
                  return ;
              }
       
              received_buf.insert(received_buf.begin()+pos2, buf2, buf2+temp_received2);
       
              pos2 += temp_received2;
          }

          ConstBufferPtr receive_CBP (new const Buffer(received_buf.begin(), received_buf.end()));

          uint8_t id =  received_buf.at(4);

          switch(id)
          {
            case sbt::msg::MsgId::MSG_ID_BITFIELD:
            {


              if (std::find(m_listen_list.begin(), m_listen_list.end(), fd) != m_listen_list.end())
              {

                ConstBufferPtr bitFieldSend(new const Buffer(m_bitfield.begin(),m_bitfield.end()));
                sbt::msg::Bitfield btf(bitFieldSend);
                ConstBufferPtr BF = btf.encode();
                
                 send(fd, BF->buf(), BF->size(), 0);

              }
              else
              {


                  ConstBufferPtr bitfield_CBP (new const Buffer(received_buf.begin(), received_buf.end()));
                  sbt::msg::Bitfield Otherbtf(bitfield_CBP);
                  Otherbtf.decode(bitfield_CBP);

                  std::vector<uint8_t> otherBitfield(Otherbtf.getBitfield()->buf(),Otherbtf.getBitfield()->buf()+received_length_int-1);

                  bool needOthers=false;
                  std::vector<size_t> piecesNeeded;


                  for (unsigned i = 0; i < otherBitfield.size(); i ++)
                  {
                    otherBitfield[i] = (otherBitfield[i] * 0x0202020202ULL & 0x010884422010ULL) % 1023;
                  }
                  initializePeerBitfield(m_inverseList[fd],otherBitfield);


                  for(int i=0;i<m_numPieces;i++)
                  {
                    //otherBitfield.resize(m_bitfield.size(), 0);

                    if((!hasPiece(m_bitfield,i)) && hasPiece(otherBitfield,i))
                    { 

                      needOthers=true;
                      piecesNeeded.push_back(i);
                    }
                  }


                  if(needOthers)
                  {

                    //send Interested msg
                    m_pieceNeed.insert(std::pair<int, std::vector<size_t>>(fd, piecesNeeded));

                    sbt::msg::Interested itrstd;
                    ConstBufferPtr itrContent=itrstd.encode();
                    send(fd, itrContent->buf(), itrContent->size(), 0);
                  }
                  else
                  {
                    //send NotInterested msg
                    sbt::msg::NotInterested not_itrstd;
                    ConstBufferPtr not_itrContent=not_itrstd.encode();
                    send(fd, not_itrContent->buf(), not_itrContent->size(), 0);
                  }
              }
            
    

              break;
            }
            case sbt::msg::MsgId::MSG_ID_INTERESTED:
            {

                sbt::msg::Unchoke uck;
                ConstBufferPtr uckContent=uck.encode();
                send(fd, uckContent->buf(), uckContent->size(), 0);

               std::cout << "receive interested!!!!" << std::endl;
               break;
            }
            case sbt::msg::MsgId::MSG_ID_NOT_INTERESTED:
            {
              std::cout << "receive not interested!!!!" << std::endl;
              break;
            }
            case sbt::msg::MsgId::MSG_ID_UNCHOKE:
            {


              for (std::map<int,bool>::iterator it=m_unchoke.begin(); it!=m_unchoke.end(); ++it)
              {
                if (it->second)
                  it->second = false;
              }

              m_unchoke.insert(std::pair<int,bool>(fd,true));


            
              break;
            }
            case sbt::msg::MsgId::MSG_ID_CHOKE:
            {
              std::cout << "receive CHOKE!!!!" << std::endl;
              break;
            }
            case sbt::msg::MsgId::MSG_ID_REQUEST:
            {
              std::cout << "receive REQUEST!!!!" << std::endl;

              ConstBufferPtr msg_CBP3 (new const Buffer(received_buf.begin(), received_buf.end()));
              sbt::msg::Request rqst;
              rqst.decode(msg_CBP3);

              int length = rqst.getLength();
              char* bufToUse = new char[length];
              readPieceToBuffer(bufToUse, rqst.getIndex(), length);

              Buffer send_Thing;
              send_Thing.insert(send_Thing.begin(), bufToUse, bufToUse+length);
              ConstBufferPtr msg_CBP4 (new const Buffer(send_Thing.begin(), send_Thing.end()));

              //send Piece
              sbt::msg::Piece pc(rqst.getIndex(),rqst.getBegin(), msg_CBP4);
              ConstBufferPtr pcContent=pc.encode();
              send(fd, pcContent->buf(), pcContent->size(), 0);
              m_fdToPieceNum.push_back(std::make_pair(fd,rqst.getIndex()));
              break;
            }
            case sbt::msg::MsgId::MSG_ID_PIECE:
            {

              sbt::msg::Piece pc1;
              pc1.decode(receive_CBP);


              std::vector<uint8_t> Pieces = m_metaInfo.getPieces();
             
              std::string hash = std::string(Pieces.begin() + pc1.getIndex() * 20, Pieces.begin() + (pc1.getIndex() + 1) * 20);

              std::vector<uint8_t> text_vec(pc1.getBlock()->begin(), pc1.getBlock()->end());


              std::string text(text_vec.begin(), text_vec.end());

              int lastPieceLength = m_metaInfo.getLength() - m_metaInfo.getPieceLength() * (m_numPieces - 1);

              if ((int)pc1.getIndex() == m_numPieces - 1)
              {
                text = text.substr(0, lastPieceLength);
              }


              if(validatePiece(text,hash))
              {



                //std::cout << text.length() << std::endl;
                if ((int)pc1.getIndex() == m_numPieces - 1)
                   writePieceToDisk((char*)pc1.getBlock()->buf(), (int)pc1.getIndex(), lastPieceLength);

                else
                   writePieceToDisk((char*)pc1.getBlock()->buf(), (int)pc1.getIndex(), (int)m_metaInfo.getPieceLength());

                updateSelfBitfield(pc1.getIndex());
                updateTrackerRequest(0,text.length());

                // updateTrackerRequest(0,text.length());

                sbt::msg::Have hv1(pc1.getIndex());
                ConstBufferPtr hvContent=hv1.encode();
                broadcastHaveMsg(pc1.getIndex()); //send to all peers
                updateSelfBitfield((int)pc1.getIndex());


              }
              else
              {

                sbt::msg::Request rqst(pc1.getIndex(), 0, m_metaInfo.getPieceLength()); //request the missing piece
                ConstBufferPtr rqstContent=rqst.encode();
                send(fd, rqstContent->buf(), rqstContent->size(), 0);
                std::cout<<"validate fail" << std::endl;
                // request again
              }

              break;
            }
            case sbt::msg::MsgId::MSG_ID_HAVE:
            {
              sbt::msg::Have hv2;
              hv2.decode(receive_CBP);
              int pcNum=(int)hv2.getIndex();
              if(std::find(m_fdToPieceNum.begin(), m_fdToPieceNum.end(), std::make_pair(fd, pcNum))!=m_fdToPieceNum.end())
                updatePeerBitfield( m_inverseList[fd], pcNum);
              int lastPieceLength = m_metaInfo.getLength() - m_metaInfo.getPieceLength() * (m_numPieces - 1);
              if(pcNum==m_numPieces-1)
                updateTrackerRequest(lastPieceLength, 0);
              else
                updateTrackerRequest(m_metaInfo.getPieceLength(), 0);
              std::cout << "receive have!!!!" << std::endl;
              break;
            }
            case sbt::msg::MsgId::MSG_ID_CANCEL:
            {
              std::cout << "cancel!!!!" << std::endl;
              break;
            }
            case sbt::msg::MsgId::MSG_ID_KEEP_ALIVE:
            {
              std::cout << "keep alive!!!!" << std::endl;
              break;
            }
          }

        }

        if (!m_unchoke.empty())
        {
              for (std::map<int,bool>::iterator it=m_unchoke.begin(); it!=m_unchoke.end(); ++it)
              {

                  if (it->second)
                  {
  
                  for (unsigned i = 0 ; i < m_pieceNeed[it->first].size(); i ++)
                  {

                        if (m_requested.find(m_pieceNeed[it->first][i]) == m_requested.end())
                        {

                          m_requested.insert(m_pieceNeed[it->first][i]);

                          if ((int)m_pieceNeed[it->first][i] == m_numPieces - 1)
                          {
                              int lastPieceLength = m_metaInfo.getLength() - m_metaInfo.getPieceLength() * (m_numPieces - 1);

                              sbt::msg::Request rqst(m_pieceNeed[it->first][i], 0,lastPieceLength); //request the missing piece
                              ConstBufferPtr rqstContent=rqst.encode();
                              send(it->first, rqstContent->buf(), rqstContent->size(), 0);

                          }
                          else
                          {
                              sbt::msg::Request rqst(m_pieceNeed[it->first][i], 0, m_metaInfo.getPieceLength()); //request the missing piece
                              ConstBufferPtr rqstContent=rqst.encode();
                              send(it->first, rqstContent->buf(), rqstContent->size(), 0);
                          }

                          break;

                        }


                    }

                    it->second = false;

                    it ++;

                    if (it != m_unchoke.end())
                      it->second = true;
                    else
                      m_unchoke.begin()->second = true;

                    it--;

                    break;

                  }
              }   
          }
      }

    }

    gettimeofday(&new_tv, NULL);

  }
    

  
  
}



void
Client::connectTracker()
{
  m_trackerSock = socket(AF_INET, SOCK_STREAM, 0);

  struct addrinfo hints;
  struct addrinfo* res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET; // IPv4
  hints.ai_socktype = SOCK_STREAM;

  // get address
  int status = 0;
  if ((status = getaddrinfo(m_trackerHost.c_str(), m_trackerPort.c_str(), &hints, &res)) != 0)
    throw Error("Cannot resolver tracker ip");

  struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
  char ipstr[INET_ADDRSTRLEN] = {'\0'};
  inet_ntop(res->ai_family, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
  // std::cout << "tracker address: " << ipstr << ":" << ntohs(ipv4->sin_port) << std::endl;

  if (connect(m_trackerSock, res->ai_addr, res->ai_addrlen) == -1) {
    perror("connect");
    throw Error("Cannot connect tracker");
  }

  freeaddrinfo(res);
}

void
Client::sendTrackerRequest()
{
  TrackerRequestParam param;

  param.setInfoHash(m_metaInfo.getHash());
  param.setPeerId("SIMPLEBT.TEST.PEERID");
  param.setIp(m_myIP);
  param.setPort(m_clientPort);
  param.setUploaded(m_uploaded); //TODO:
  param.setDownloaded(m_downloaded); //TODO:
  param.setLeft(m_left); //TODO:
  if (m_isFirstReq)
    param.setEvent(TrackerRequestParam::STARTED);
  if (m_isComplete)
    param.setEvent(TrackerRequestParam::COMPLETED);

  // std::string path = m_trackerFile;
  std::string path = m_metaInfo.getAnnounce();
  path += param.encode();

  // param.print(std::cout);

  HttpRequest request;
  request.setMethod(HttpRequest::GET);
  request.setHost(m_trackerHost);
  request.setPort(boost::lexical_cast<uint16_t>(m_trackerPort));
  request.setPath(path);
  request.setVersion("1.0");

  Buffer buffer(request.getTotalLength());

  request.formatRequest(reinterpret_cast<char *>(buffer.buf()));

  send(m_trackerSock, buffer.buf(), buffer.size(), 0);
}

TrackerResponse
Client::recvTrackerResponse(bool& good_response)
{
  TrackerResponse trackerResponse;
  std::stringstream headerOs;
  std::stringstream bodyOs;

  char buf[512] = {0};
  char lastTree[3] = {0};

  bool hasEnd = false;
  bool hasParseHeader = false;
  HttpResponse response;

  uint64_t bodyLength = 0;

  while (true) {
    memset(buf, '\0', sizeof(buf));
    memcpy(buf, lastTree, 3);

    ssize_t res = recv(m_trackerSock, buf + 3, 512 - 3, 0);

    if (res == -1) {
      perror("recv");
      good_response = false;
      return trackerResponse;
    }

    const char* endline = 0;

    if (!hasEnd)
      endline = (const char*)memmem(buf, res, "\r\n\r\n", 4);

    if (endline != 0) {
      const char* headerEnd = endline + 4;

      headerOs.write(buf + 3, (endline + 4 - buf - 3));

      if (headerEnd < (buf + 3 + res)) {
        bodyOs.write(headerEnd, (buf + 3 + res - headerEnd));
      }

      hasEnd = true;
    }
    else {
      if (!hasEnd) {
        memcpy(lastTree, buf + res, 3);
        headerOs.write(buf + 3, res);
      }
      else
        bodyOs.write(buf + 3, res);
    }

    if (hasEnd) {
      if (!hasParseHeader) {
        response.parseResponse(headerOs.str().c_str(), headerOs.str().size());
        hasParseHeader = true;

        bodyLength = boost::lexical_cast<uint64_t>(response.findHeader("Content-Length"));
      }
    }

    if (hasParseHeader && bodyOs.str().size() >= bodyLength)
      break;
  }

  close(m_trackerSock);
  FD_CLR(m_trackerSock, &m_readSocks);


  bencoding::Dictionary dict;

  std::stringstream tss;
  tss.str(bodyOs.str());
  dict.wireDecode(tss);

  trackerResponse.decode(dict);
  m_interval = trackerResponse.getInterval();


  m_isFirstRes = false;
  good_response = true;

  return trackerResponse;
}

void
Client::broadcastHaveMsg(int pieceIndex) 
{
  for(std::map<std::string, int>::iterator it = m_connectionlist.begin(); it != m_connectionlist.end(); it++) {
    msg::Have hv(pieceIndex);
    ConstBufferPtr hvcontent = hv.encode();
    send(it->second, hvcontent->buf(), hvcontent->size(), 0);
  }
}


bool
Client::validatePiece(const std::string& text, const std::string& hash) 
{

  return util::sha1(text).compare(hash) == 0 ? true : false;
}
 
bool
Client::hasPiece(std::vector<uint8_t> bitfield, int pieceIndex) 
{
  return bitfield[pieceIndex / 8] & (1 << pieceIndex % 8);
}

bool
Client::requestPiece(int pieceIndex) 
{
  if (m_requested.find(pieceIndex) == m_requested.end())
  {
    m_requested.insert(pieceIndex);
    return true;
  }
  else
    return false;

}
 
void
Client::writePieceToDisk(const char* buffer, int pieceIndex, int pieceLength) 
{
  std::fstream f(m_metaInfo.getName(), std::fstream::in | std::fstream::out);
  f.seekp(pieceIndex * m_metaInfo.getPieceLength(), f.beg);
  f.write(buffer, pieceLength);
  m_bitfield[pieceIndex / 8] |= 1 << (pieceIndex % 8);
 
  f.close();
}
 
void
Client::readPieceToBuffer(char* buffer, int pieceIndex, int pieceLength)
{
  std::fstream f(m_metaInfo.getName(), std::fstream::in | std::fstream::out);
  f.seekg(pieceIndex * m_metaInfo.getPieceLength(), f.beg);
  f.readsome(buffer, pieceLength);
 
  f.close();
}

const std::string
Client::getMyIP() 
{
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_in *sa;
  char *addr;
  std::string s;

  getifaddrs (&ifap);
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr->sa_family == AF_INET && !strcmp(ifa->ifa_name, "eth0")) {
          sa = (struct sockaddr_in *) ifa->ifa_addr;
          addr = inet_ntoa(sa->sin_addr);
          s = addr;
      }
  }

  freeifaddrs(ifap);

  return s;
}

void
Client::initializePeerBitfield(std::string peerid, std::vector<uint8_t> bitfield) {
  bitfield.resize(m_bitfield.size(), '\0');
  m_peerbitfields.insert(std::pair<std::string, std::vector<uint8_t> >(peerid, bitfield));
}

void
Client::updatePeerBitfield(std::string peerid, int pieceIndex) {
  m_peerbitfields[peerid][pieceIndex / 8] |= 1 << (pieceIndex % 8);
}

void
Client::updateSelfBitfield(int pieceIndex) {
  m_bitfield[pieceIndex/8] |=1 << (pieceIndex % 8);
}

void
Client::updateTrackerRequest(int up, int down) 
{
  m_uploaded += up;
  m_downloaded += down;
  m_isComplete = false;
  if (m_left > 0) 
  {
    m_left -= down;

    if (m_left <= 0)
    {
      m_left = 0;
      m_isComplete = true;
    }

  }
}


} // namespace sbt





