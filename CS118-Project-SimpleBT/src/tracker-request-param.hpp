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

#ifndef SBT_TRACKER_REQUEST_PARAM_HPP
#define SBT_TRACKER_REQUEST_PARAM_HPP

#include "common.hpp"
#include "util/buffer.hpp"

namespace sbt {

class TrackerRequestParam
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
  void
  setInfoHash(ConstBufferPtr infoHash)
  {
    m_infoHash = infoHash;
  }

  ConstBufferPtr
  getInfoHash() const
  {
    return m_infoHash;
  }

  void
  setPeerId(const std::string& peerId)
  {
    m_peerId = peerId;
  }

  std::string
  getPeerId() const
  {
    return m_peerId;
  }

  void
  setIp(const std::string& ip)
  {
    m_ip = ip;
  }

  std::string
  getIp() const
  {
    return m_ip;
  }

  void
  setPort(uint16_t port)
  {
    m_port = port;
  }

  uint16_t
  getPort() const
  {
    return m_port;
  }

  void
  setUploaded(uint64_t uploaded)
  {
    m_uploaded = uploaded;
  }

  uint64_t
  getUploaded() const
  {
    return m_uploaded;
  }

  void
  setDownloaded(uint64_t downloaded)
  {
    m_downloaded = downloaded;
  }

  uint64_t
  getDownloaded() const
  {
    return m_downloaded;
  }

  void
  setLeft(uint64_t left)
  {
    m_left = left;
  }

  uint64_t
  getLeft() const
  {
    return m_left;
  }

  void
  setEvent(const std::string& event)
  {
    m_event = event;
  }

  std::string
  getEvent() const
  {
    return m_event;
  }

  std::string
  encode();

  void
  decode(const std::string& input);

  void
  print(std::ostream& os);

public:
  static const std::string STARTED;
  static const std::string STOPPED;
  static const std::string COMPLETED;

private:
  ConstBufferPtr m_infoHash;
  std::string m_peerId;
  std::string m_ip;
  uint16_t m_port;
  uint64_t m_uploaded;
  uint64_t m_downloaded;
  uint64_t m_left;
  std::string m_event;
};

} // namespace sbt

#endif // SBT_TRACKER_REQUEST_PARAM_HPP
