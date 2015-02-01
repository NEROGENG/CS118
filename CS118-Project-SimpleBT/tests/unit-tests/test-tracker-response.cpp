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

#include "tracker-response.hpp"
#include <sstream>

#include "boost-test.hpp"

namespace sbt {
namespace test {


BOOST_AUTO_TEST_SUITE(TestTrackerResponse)

BOOST_AUTO_TEST_CASE(TestPeerInfo)
{
  PeerInfo info;

  std::string peerId("abcdefghjkABCDEFGHJK");
  std::string ip("127.0.0.1");
  uint16_t port = 12345;

  info.peerId = peerId;
  info.ip = ip;
  info.port = port;

  shared_ptr<bencoding::Dictionary> encode = info.encode();

  std::stringstream ss;
  encode->wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "d2:ip9:127.0.0.17:peer id20:abcdefghjkABCDEFGHJK4:porti12345ee");

  ss.str("d2:ip9:127.0.0.17:peer id20:abcdefghjkABCDEFGHJK4:porti12345ee");
  bencoding::Dictionary dict2;
  dict2.wireDecode(ss);

  PeerInfo info2;
  info2.decode(dict2);
  BOOST_CHECK_EQUAL(info2.peerId, peerId);
  BOOST_CHECK_EQUAL(info2.ip, ip);
  BOOST_CHECK_EQUAL(info2.port, port);
}

BOOST_AUTO_TEST_CASE(Basic)
{
  TrackerResponse response;

  BOOST_CHECK_EQUAL(response.isFailure(), true);
  BOOST_CHECK_EQUAL(response.getFailure(), "response is not initialize");

  TrackerResponse response1(100);

  BOOST_CHECK_EQUAL(response1.isFailure(), false);
  BOOST_CHECK_EQUAL(response1.getInterval(), 100);

  PeerInfo info;
  std::string peerId("abcdefghjkABCDEFGHJK");
  std::string ip("127.0.0.1");
  uint16_t port = 12345;
  info.peerId = peerId;
  info.ip = ip;
  info.port = port;

  response1.addPeer(info);
  shared_ptr<bencoding::Dictionary> encoded = response1.encode();

  std::stringstream ss;
  encoded->wireEncode(ss);
  std::string result =
    "d"
      "8:intervali100e"
      "5:peers"
        "l"
          "d"
            "2:ip9:127.0.0.1"
            "7:peer id20:abcdefghjkABCDEFGHJK"
            "4:porti12345e"
          "e"
        "e"
    "e";

  BOOST_CHECK_EQUAL(ss.str(), result);

  TrackerResponse response10;
  response10.decode(*encoded);

  BOOST_CHECK_EQUAL(response10.isFailure(), false);
  BOOST_CHECK_EQUAL(response10.getInterval(), 100);
  BOOST_CHECK_EQUAL(response10.getPeers().size(), 1);

  TrackerResponse response2("no torrent");

  BOOST_CHECK_EQUAL(response2.isFailure(), true);
  BOOST_CHECK_EQUAL(response2.getFailure(), "no torrent");

  shared_ptr<bencoding::Dictionary> encoded2 = response2.encode();

  ss.str("");
  encoded2->wireEncode(ss);
  std::string result2 =
    "d"
      "7:failure10:no torrent"
    "e";

  BOOST_CHECK_EQUAL(ss.str(), result2);

  TrackerResponse response20;
  response20.decode(*encoded2);

  BOOST_CHECK_EQUAL(response20.isFailure(), true);
  BOOST_CHECK_EQUAL(response20.getFailure(), "no torrent");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace sbt
