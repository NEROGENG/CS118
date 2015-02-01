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

#include "msg/handshake.hpp"

#include "boost-test.hpp"

namespace sbt {
namespace msg {
namespace test {

BOOST_AUTO_TEST_SUITE(TestHandshake)

BOOST_AUTO_TEST_CASE(Encode)
{
  ConstBufferPtr fakeInfoHash = std::make_shared<Buffer>(20, 1);
  std::string peerId("PEERID12340000000000");
  uint8_t encoded_raw[] = {
    0x13,
    0x42, 0x69, 0x74, 0x54, 0x6f, 0x72, 0x72, 0x65, 0x6e, 0x74,
    0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x50, 0x45, 0x45, 0x52, 0x49, 0x44, 0x31, 0x32, 0x33, 0x34,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
  };

  HandShake msg;
  msg.setInfoHash(fakeInfoHash);
  msg.setPeerId(peerId);

  ConstBufferPtr encoded = msg.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->buf(), encoded->buf() + encoded->size(),
                                  encoded_raw, encoded_raw + sizeof(encoded_raw));
}

BOOST_AUTO_TEST_CASE(Decode)
{
  ConstBufferPtr fakeInfoHash = std::make_shared<Buffer>(20, 1);
  std::string peerId("PEERID12340000000000");
  uint8_t encoded_raw[] = {
    0x13,
    0x42, 0x69, 0x74, 0x54, 0x6f, 0x72, 0x72, 0x65, 0x6e, 0x74,
    0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x50, 0x45, 0x45, 0x52, 0x49, 0x44, 0x31, 0x32, 0x33, 0x34,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
  };

  ConstBufferPtr encoded = std::make_shared<Buffer>(encoded_raw, sizeof(encoded_raw));

  HandShake msg;
  BOOST_REQUIRE_NO_THROW(msg.decode(encoded));

  ConstBufferPtr infoHash = msg.getInfoHash();
  BOOST_REQUIRE_EQUAL_COLLECTIONS(infoHash->buf(), infoHash->buf() + infoHash->size(),
                                  fakeInfoHash->buf(), fakeInfoHash->buf() + fakeInfoHash->size());

  BOOST_CHECK_EQUAL(peerId, msg.getPeerId());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace msg
} // namespace sbt
