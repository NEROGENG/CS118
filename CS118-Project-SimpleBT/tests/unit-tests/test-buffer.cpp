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

#include "util/buffer.hpp"
#include <sstream>

#include "boost-test.hpp"

namespace sbt {
namespace util {
namespace test {

BOOST_AUTO_TEST_SUITE(TestBuffer)

BOOST_AUTO_TEST_CASE(Print)
{
  uint8_t hash[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  Buffer buffer(hash, sizeof(hash));

  std::stringstream ss;
  buffer.print(ss);

  BOOST_CHECK_EQUAL("0123456789abcdef", ss.str());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace util
} // namespace sbt
