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

#include "tracker-request-param.hpp"
#include "http/url-encoding.hpp"
#include <sstream>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>

namespace sbt {

const std::string TrackerRequestParam::STARTED("started");
const std::string TrackerRequestParam::STOPPED("stopped");
const std::string TrackerRequestParam::COMPLETED("completed");

std::string
TrackerRequestParam::encode()
{
  std::stringstream ss;

  if (static_cast<bool>(m_infoHash))
    ss << "?info_hash=" << url::encode(m_infoHash->buf(), m_infoHash->size());
  else
    throw Error("No info hash!");

  if (!m_peerId.empty())
    ss << "&peer_id=" << m_peerId;
  else
    throw Error("No peer id!");

  if (!m_ip.empty())
    ss << "&ip=" << m_ip;


  ss << "&port=" << m_port;
  ss << "&uploaded=" << m_uploaded;
  ss << "&downloaded=" << m_downloaded;
  ss << "&left=" << m_left;

  if (m_event == STARTED ||
      m_event == STOPPED ||
      m_event == COMPLETED) {
    ss << "&event=" << m_event;
  }
  else if (!m_event.empty())
    throw Error("Wrong event");

  return ss.str();
}

void
TrackerRequestParam::decode(const std::string& input)
{
  if (input[0] != '?')
    throw Error("Wrong request param");

  std::string paramStr = input.substr(1);
  boost::tokenizer<boost::char_separator<char>> tokens(paramStr,
                                                       boost::char_separator<char>("&"));

  for (const auto& token : tokens) {
    size_t sep = token.find('=');

    if (sep == std::string::npos)
      throw Error("Wrong param format");

    std::string key = token.substr(0, sep);
    std::string value = token.substr(sep + 1);

    if (key == "info_hash")
      m_infoHash = url::decode(value);
    else if (key == "peer_id")
      m_peerId = value;
    else if (key == "ip")
      m_ip = value;
    else if (key == "port")
      m_port = boost::lexical_cast<uint16_t>(value);
    else if (key == "uploaded")
      m_uploaded = boost::lexical_cast<uint64_t>(value);
    else if (key == "downloaded")
      m_downloaded = boost::lexical_cast<uint64_t>(value);
    else if (key == "left")
      m_left = boost::lexical_cast<uint64_t>(value);
    else if (key == "event") {
        if (value == STARTED ||
            value == STOPPED ||
            value == COMPLETED) {
          m_event = value;
        }
        else
          throw Error("Wrong event value");
    }
    else
      throw Error("Wrong param key");
  }
}

void
TrackerRequestParam::print(std::ostream& os)
{
  if (!static_cast<bool>(m_infoHash))
    os << "info_hash: N/A" << std::endl;
  else {
    os << "info_hash: ";
    m_infoHash->print(os);
    os << std::endl;
  }

  os << "peer_id: " << m_peerId << std::endl;
  os << "ip: " << m_ip << std::endl;
  os << "port: " << m_port << std::endl;
  os << "uploaded: " << m_uploaded <<  std::endl;
  os << "downloaded: " << m_downloaded << std::endl;
  os << "left: " << m_left << std::endl;
  os << "event: " << m_event << std::endl;
}

} // namespace sbt
