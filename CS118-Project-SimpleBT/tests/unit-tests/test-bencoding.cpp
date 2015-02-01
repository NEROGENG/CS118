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

#include "util/bencoding.hpp"
#include <sstream>

#include "boost-test.hpp"

namespace sbt {
namespace bencoding {
namespace test {

BOOST_AUTO_TEST_SUITE(TestBencoding)

BOOST_AUTO_TEST_CASE(TestString)
{
  std::stringstream ss;

  String str1("abc");
  str1.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "3:abc");

  ss.str("");

  uint8_t array[] = {0x41, 0x42, 0x43};
  String str2(array, 3);
  str2.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "3:ABC");

  ss.str("");

  String str3("");
  str3.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "0:");

  ss.str("2:ab");
  std::string val4("ab");
  String str4;
  str4.wireDecode(ss);
  BOOST_REQUIRE_EQUAL_COLLECTIONS(str4.getValue().begin(), str4.getValue().end(),
                                  val4.begin(), val4.end());

  ss.str("-1:ab");
  String str5;
  BOOST_CHECK_THROW(str5.wireDecode(ss), bencoding::Error);

  ss.str("A:ab");
  String str6;
  BOOST_CHECK_THROW(str6.wireDecode(ss), bencoding::Error);

  ss.str("0:ab");
  String str7;
  str7.wireDecode(ss);
  BOOST_CHECK_EQUAL(str7.size(), 0);
  BOOST_CHECK_EQUAL(static_cast<bool>(str7.value()), false);

  ss.str("01:a");
  String str8;
  BOOST_CHECK_THROW(str8.wireDecode(ss), bencoding::Error);

  ss.str("00:a");
  String str9;
  BOOST_CHECK_THROW(str9.wireDecode(ss), bencoding::Error);

  ss.str("-0:a");
  String str10;
  BOOST_CHECK_THROW(str10.wireDecode(ss), bencoding::Error);

  ss.str("123");
  String str11;
  BOOST_CHECK_THROW(str11.wireDecode(ss), bencoding::Error);
}

BOOST_AUTO_TEST_CASE(TestInteger)
{
  std::stringstream ss;

  Integer i0;
  BOOST_CHECK_EQUAL(i0.getValue(), 0);
  i0.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "i0e");

  ss.str("");

  Integer i1(1);
  BOOST_CHECK_EQUAL(i1.getValue(), 1);
  i1.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "i1e");

  ss.str("");

  Integer i2(-1);
  i2.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "i-1e");

  ss.str("i2e");
  Integer i3;
  i3.wireDecode(ss);
  BOOST_CHECK_EQUAL(i3.getValue(), 2);

  ss.str("i0e");
  Integer i4;
  i4.wireDecode(ss);
  BOOST_CHECK_EQUAL(i4.getValue(), 0);

  ss.str("i-2e");
  Integer i5;
  i5.wireDecode(ss);
  BOOST_CHECK_EQUAL(i5.getValue(), -2);

  ss.str("-2e");
  BOOST_CHECK_THROW(Integer().wireDecode(ss), bencoding::Error);

  ss.str("i2");
  BOOST_CHECK_THROW(Integer().wireDecode(ss), bencoding::Error);

  ss.str("iae");
  BOOST_CHECK_THROW(Integer().wireDecode(ss), bencoding::Error);

  ss.str("i00e");
  BOOST_CHECK_THROW(Integer().wireDecode(ss), bencoding::Error);

  ss.str("i-0e");
  BOOST_CHECK_THROW(Integer().wireDecode(ss), bencoding::Error);

  ss.str("i01e");
  BOOST_CHECK_THROW(Integer().wireDecode(ss), bencoding::Error);

  ss.str("i-01e");
  BOOST_CHECK_THROW(Integer().wireDecode(ss), bencoding::Error);
}

BOOST_AUTO_TEST_CASE(TestList)
{
  std::stringstream ss;

  auto i0 = std::make_shared<Integer>(0);
  auto i1 = std::make_shared<Integer>(1);

  std::string str0("abc");
  std::string str1("edf");
  auto s0 = std::make_shared<String>(str0);
  auto s1 = std::make_shared<String>(str1);

  List list;

  list.append(i0);
  list.append(s0);
  list.append(i1);
  list.append(s1);

  list.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "li0e3:abci1e3:edfe");


  ss.str("li0e3:abci1e3:edfe");

  List list2;
  list2.wireDecode(ss);
  List::iterator it = list2.begin();
  BOOST_CHECK_EQUAL((*it)->getType(), TYPE_INTEGER);
  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<Integer>(*it)->getValue(), 0);

  it++;
  BOOST_CHECK_EQUAL((*it)->getType(), TYPE_STRING);
  BOOST_REQUIRE_EQUAL_COLLECTIONS(std::dynamic_pointer_cast<String>(*it)->value(),
                                  std::dynamic_pointer_cast<String>(*it)->value() + 3,
                                  str0.begin(),
                                  str0.end());

  it++;
  BOOST_CHECK_EQUAL((*it)->getType(), TYPE_INTEGER);
  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<Integer>(*it)->getValue(), 1);

  it++;
  BOOST_CHECK_EQUAL((*it)->getType(), TYPE_STRING);
  BOOST_REQUIRE_EQUAL_COLLECTIONS(std::dynamic_pointer_cast<String>(*it)->value(),
                                  std::dynamic_pointer_cast<String>(*it)->value() + 3,
                                  str1.begin(),
                                  str1.end());

  ss.str("li0eli1eei2ee");
  List list3;
  list3.wireDecode(ss);
  it = list3.begin();
  BOOST_CHECK_EQUAL((*it)->getType(), TYPE_INTEGER);
  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<Integer>(*it)->getValue(), 0);

  it++;
  BOOST_CHECK_EQUAL((*it)->getType(), TYPE_LIST);
  auto p = std::dynamic_pointer_cast<List>(*it);
  BOOST_CHECK_EQUAL((*p->begin())->getType(), TYPE_INTEGER);
  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<Integer>(*p->begin())->getValue(), 1);

  it++;
  BOOST_CHECK_EQUAL((*it)->getType(), TYPE_INTEGER);
  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<Integer>(*it)->getValue(), 2);


  ss.str("li0e");
  BOOST_CHECK_THROW(List().wireDecode(ss), bencoding::Error);

  ss.str("i0ee");
  BOOST_CHECK_THROW(List().wireDecode(ss), bencoding::Error);
}

BOOST_AUTO_TEST_CASE(TestDictionary)
{
  std::stringstream ss;

  auto i0 = std::make_shared<Integer>(0);
  auto s0 = std::make_shared<String>("abc");
  auto l0 = std::make_shared<List>();
  l0->append(i0);
  l0->append(s0);

  Dictionary dict;

  dict.insert("key0", i0);
  dict.insert("key1", s0);
  dict.insert("key2", l0);

  dict.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "d4:key0i0e4:key13:abc4:key2li0e3:abcee");

  ss.str("");

  auto d0 = std::make_shared<Dictionary>();
  d0->insert("k1", i0);
  d0->insert("k2", s0);
  d0->insert("k3", l0);

  dict.insert("key3", d0);

  dict.wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(),
                    "d4:key0i0e4:key13:abc4:key2li0e3:abce4:key3d2:k1i0e2:k23:abc2:k3li0e3:abceee");

  ss.str("d4:key0i0e4:key13:abc4:key2li0e3:abce4:key3d2:k1i0e2:k23:abc2:k3li0e3:abceee");
  Dictionary dict2;
  dict2.wireDecode(ss);

  BOOST_CHECK(static_cast<bool>(dict2.get("key0")));
  BOOST_CHECK(static_cast<bool>(dict2.get("key1")));
  BOOST_CHECK(static_cast<bool>(dict2.get("key2")));
  BOOST_CHECK(static_cast<bool>(dict2.get("key3")));
  BOOST_CHECK(!static_cast<bool>(dict2.get("key4")));

  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<Integer>(dict2.get("key0"))->getValue(), 0);
  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<String>(dict2.get("key1"))->toString(), "abc");

  auto l2 = std::dynamic_pointer_cast<List>(dict2.get("key2"));
  List::iterator it = l2->begin();
  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<Integer>(*it)->getValue(), 0);
  it++;
  BOOST_CHECK_EQUAL(std::dynamic_pointer_cast<String>(*it)->toString(), "abc");

  auto d2 = std::dynamic_pointer_cast<Dictionary>(dict2.get("key3"));
  BOOST_CHECK(static_cast<bool>(d2->get("k1")));
  BOOST_CHECK(static_cast<bool>(d2->get("k2")));
  BOOST_CHECK(static_cast<bool>(d2->get("k3")));
  BOOST_CHECK(!static_cast<bool>(d2->get("k4")));

  ss.str("d3:key");
  BOOST_CHECK_THROW(Dictionary().wireDecode(ss), bencoding::Error);

  ss.str("di1ee");
  BOOST_CHECK_THROW(Dictionary().wireDecode(ss), bencoding::Error);

  ss.str("3:keye");
  BOOST_CHECK_THROW(Dictionary().wireDecode(ss), bencoding::Error);
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace bencoding
} // namespace sbt
