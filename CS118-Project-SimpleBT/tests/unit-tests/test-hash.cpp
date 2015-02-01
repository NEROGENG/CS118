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

#include "util/hash.hpp"

#include "boost-test.hpp"

namespace sbt {
namespace util {
namespace test {

BOOST_AUTO_TEST_SUITE(TestHash)

BOOST_AUTO_TEST_CASE(Basic)
{
  uint8_t hash[] = {
    0x40, 0xbd, 0x00, 0x15, 0x63, 0x08, 0x5f, 0xc3, 0x51, 0x65,
    0x32, 0x9e, 0xa1, 0xff, 0x5c, 0x5e, 0xcb, 0xdb, 0xbe, 0xef};
  std::string expected(hash, hash + sizeof(hash));
  std::string input("123");

  std::string result = sha1(input);
  BOOST_REQUIRE_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                  result.begin(), result.end());

  std::vector<uint8_t> input2 {'1', '2', '3'};
  std::vector<uint8_t> result2 = sha1(input2);
  BOOST_REQUIRE_EQUAL_COLLECTIONS(hash, hash + sizeof(hash),
                                  result2.begin(), result2.end());

  auto input3 = make_shared<Buffer>(&input2.front(), input.size());
  ConstBufferPtr result3 = sha1(input3);
  BOOST_REQUIRE_EQUAL_COLLECTIONS(hash, hash + sizeof(hash),
                                  result3->begin(), result3->end());
}

BOOST_AUTO_TEST_CASE(Tmp)
{
  // {
  //   using namespace CryptoPP;

  //   StringSource(peerId, true,
  //                new HexEncoder(new FileSink(std::cerr), false));
  // }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace util
} // namespace sbt
