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
#include "meta-info.hpp"
#include "tracker-response.hpp"
#include "tracker-request-param.hpp"
#include "util/buffer.hpp"
#include <vector>
#include <set>
#include <map>

namespace sbt {

class Client
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

public:
  Client(const std::string& port,
         const std::string& torrent);

  void
  run();

  const std::string&
  getTrackerHost() {
    return m_trackerHost;
  }

  const std::string&
  getTrackerPort() {
    return m_trackerPort;
  }

  const std::string&
  getTrackerFile() {
    return m_trackerFile;
  }

private:
  void
  loadMetaInfo(const std::string& torrent);

  void
  connectTracker();

  void
  sendTrackerRequest();

    bool
  checkFile(const std::string& filename);

  void
  checkFileOrCreate();

  TrackerResponse
  recvTrackerResponse(bool& good_response);

  void
  broadcastHaveMsg(int pieceIndex);

  bool
  requestPiece(int pieceIndex);

  void 
  readPieceToBuffer(char* buffer, int pieceIndex, int pieceLength);

  void 
  writePieceToDisk(const char* buffer, int pieceIndex, int pieceLength);

  bool 
  validatePiece(const std::string& text, const std::string& hash);
 
  bool hasPiece(std::vector<uint8_t> bitfield, int pieceIndex);

  void
  initializePeerBitfield(std::string peerid, std::vector<uint8_t> bitfield);

  void
  updatePeerBitfield(std::string peerid, int pieceIndex);

  void
  updateTrackerRequest(int up, int down);

  void
  updateSelfBitfield(int pieceIndex);

  const std::string getMyIP();

private:
  MetaInfo m_metaInfo;
  std::string m_trackerHost;
  std::string m_trackerPort;
  std::string m_trackerFile;
  std::string m_myIP;

  uint16_t m_clientPort;

  int m_trackerSock;
  int m_serverSock = -1;

  fd_set m_readSocks;

  uint64_t m_interval;
  bool m_isFirstReq;
  bool m_isFirstRes;
  bool m_isComplete;

  int m_numPieces;
  std::vector<uint8_t> m_bitfield;
  std::vector<PeerInfo> m_peerlist;
  std::map<std::string, int> m_connectionlist;
  std::map<int, std::string> m_inverseList;
  std::vector<std::pair<int, int>> m_fdToPieceNum;
  std::vector<int> m_listen_list;
  std::map<std::string, std::vector<uint8_t> > m_peerbitfields;
  std::set<int> m_requested;
  std::map<int, bool> m_unchoke;
  std::map<int, std::vector<size_t>> m_pieceNeed;

  int m_uploaded;
  int m_downloaded;
  int m_left;

  bool good_response;

};

} // namespace sbt

#endif // SBT_CLIENT_HPP
