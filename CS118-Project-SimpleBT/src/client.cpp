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
#include "util/hash.hpp"
#include "util/buffer.hpp"
#include "msg/msg-base.hpp"
#include <fstream>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>


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
#include <ifaddrs.h>
#include <vector>
#include <map>
#include <cmath>



namespace sbt {

Client::Client(const std::string& port, const std::string& torrent)
  : m_interval(3600)
  , m_isFirstReq(true)
  , m_isFirstRes(true)
{
  srand(time(NULL));

  m_clientPort = boost::lexical_cast<uint16_t>(port);

  m_myIP = getMyIP();
  m_uploaded = 0;
  m_downloaded = 0;
  m_left = 0;

  loadMetaInfo(torrent);

  m_numPieces = ceil((double)m_metaInfo.getLength()/(double)m_metaInfo.getPieceLength());
  // std::cout << "Number of Pieces: " << m_numPieces << std::endl;

  checkFileOrCreate();

  // char array[2048];
  // for (int i = 0; i < 22; i++) {
  //   readPieceToBuffer(array, i, 2048);
  //   writePieceToDisk(array, i, 2048);
  // }
  // int lastPieceLength = m_metaInfo.getLength() - m_metaInfo.getPieceLength() * (m_numPieces - 1);
  // readPieceToBuffer(array, 22, lastPieceLength);
  // writePieceToDisk(array, 22, lastPieceLength);

  run();
}

void
Client::run()
{
  while (true) {
    connectTracker();
    sendTrackerRequest();
    m_isFirstReq = false;
    recvTrackerResponse();
    close(m_trackerSock);
    sleep(m_interval);
  }
}

void
Client::checkFileOrCreate() { 
  if (checkFile(m_metaInfo.getName()))
    std::cout << m_metaInfo.getName() << " exists!" << std::endl;
  else {
    std::cout << m_metaInfo.getName() << " does not exist! Let's create one!" << std::endl;

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
  if (hasPiece(m_bitfield, m_numPieces - 1)
    m_left += m_metaInfo.getLength() - m_metaInfo.getPieceLength() * (m_numPieces - 1);
  m_left = m_metaInfo.getLength() - m_left;

  std::cout << "Left: " << m_left << endl;

  // char array [3] = {'x', 'y', 'z'};
  // writePieceToDisk(array, 0, 3);

  ConstBufferPtr CBP(new const Buffer(m_bitfield.begin(), m_bitfield.end()));

  std::cout << "Bitfield: ";
  CBP->print(std::cout);
  std::cout << std::endl;
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
    std::string temp = std::string(v.begin() + i * 20, v.begin() + (i + 1) * 20);
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
  if (param.getLeft() == 0)
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

void
Client::recvTrackerResponse()
{
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
      return;
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

  TrackerResponse trackerResponse;
  trackerResponse.decode(dict);
  const std::vector<PeerInfo>& peers = trackerResponse.getPeers();
  m_interval = trackerResponse.getInterval();

  if (m_isFirstRes) {
    for (const auto& peer : peers) {
      std::cout << peer.ip << ":" << peer.port << std::endl;
    }
  }

  m_isFirstRes = false;
}

void
Client::broadcastHaveMsg(int pieceIndex) {
  for(std::map<std::string, int>::iterator it = m_connectionlist.begin(); it != m_connectionlist.end(); it++) {
    msg::Have hv(pieceIndex);
    ConstBufferPtr hvcontent = hv.encode();
    send(iterator->second, hvcontent.buf(), hvcontent.size(), 0);
  }
}

bool
Client::validatePiece(const std::string& text, const std::string& hash) {
  return util::sha1(text) == hash;
}

bool
Client::hasPiece(std::vector<uint8_t> bitfield, int pieceIndex) {
  return bitfield[pieceIndex / 8] & (1 << pieceIndex % 8);
}

void
Client::writePieceToDisk(const char* buffer, int pieceIndex, int pieceLength) {
  std::fstream f(m_metaInfo.getName(), std::fstream::in | std::fstream::out);
  f.seekp(pieceIndex * m_metaInfo.getPieceLength(), f.beg);
  f.write(buffer, pieceLength);
  m_bitfield[pieceIndex / 8] |= 1 << (pieceIndex % 8);

  f.close();
}

void
Client::readPieceToBuffer(char* buffer, int pieceIndex, int pieceLength) {
  std::fstream f(m_metaInfo.getName(), std::fstream::in | std::fstream::out);
  f.seekg(pieceIndex * m_metaInfo.getPieceLength(), f.beg);
  f.readsome(buffer, pieceLength);

  f.close();
}

void
Client::updateTrackerRequest(int up, int down) {
  m_uploaded += up;
  m_downloaded += down;
  m_left -= down;
}

const std::string
Client::getMyIP() {
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

} // namespace sbt
