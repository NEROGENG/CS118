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

#include "http/url-encoding.hpp"

#include "boost-test.hpp"

namespace sbt {
namespace test {

BOOST_AUTO_TEST_SUITE(TestUrlEncoding)

BOOST_AUTO_TEST_CASE(Basic)
{
  uint8_t input1[] = {0x01, 0x2C, 0x2D, 0x2E, 0x2F};
  BOOST_CHECK_EQUAL(url::encode(input1, 5), "%01%2C-.%2F");

  auto output1 = url::decode("%01%2C-.%2F");
  BOOST_REQUIRE_EQUAL_COLLECTIONS(output1->begin(), output1->end(),
                                  input1, input1 + sizeof(input1));

  uint8_t input2[] = {0x30, 0x39, 0x3A, 0x40, 0x41};
  BOOST_CHECK_EQUAL(url::encode(input2, 5), "09%3A%40A");

  auto output2 = url::decode("09%3A%40A");
  BOOST_REQUIRE_EQUAL_COLLECTIONS(output2->begin(), output2->end(),
                                  input2, input2 + sizeof(input2));

  uint8_t input3[] = {0x5A, 0x5B, 0x5E, 0x5F, 0x60, 0x61};
  BOOST_CHECK_EQUAL(url::encode(input3, 6), "Z%5B%5E_%60a");

  auto output3 = url::decode("Z%5B%5E_%60a");
  BOOST_REQUIRE_EQUAL_COLLECTIONS(output3->begin(), output3->end(),
                                  input3, input3 + sizeof(input3));

  uint8_t input4[] = {0x7A, 0x7B, 0x7D, 0x7E, 0x7F};
  BOOST_CHECK_EQUAL(url::encode(input4, 5), "z%7B%7D~%7F");

  auto output4 = url::decode("z%7B%7D~%7F");
  BOOST_REQUIRE_EQUAL_COLLECTIONS(output4->begin(), output4->end(),
                                  input4, input4 + sizeof(input4));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace sbt
