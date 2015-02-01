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

#include "meta-info.hpp"
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>

#include "boost-test.hpp"

namespace sbt {
namespace test {


BOOST_AUTO_TEST_SUITE(TestMetaInfo)

BOOST_AUTO_TEST_CASE(TestFile)
{
  MetaInfo::File file;

  file.length = 123;
  file.path = {"a", "b", "c"};

  std::shared_ptr<bencoding::Dictionary> encode = file.encode();

  std::stringstream ss;
  encode->wireEncode(ss);
  BOOST_CHECK_EQUAL(ss.str(), "d6:lengthi123e4:pathl1:a1:b1:cee");

  ss.str("d6:lengthi123e4:pathl1:a1:b1:cee");
  bencoding::Dictionary dict2;
  dict2.wireDecode(ss);

  MetaInfo::File file2;
  file2.decode(dict2);
  BOOST_CHECK_EQUAL(file2.length, 123);
  BOOST_CHECK_EQUAL(file2.path.size(), 3);
  BOOST_CHECK_EQUAL(file2.path[0], "a");
  BOOST_CHECK_EQUAL(file2.path[1], "b");
  BOOST_CHECK_EQUAL(file2.path[2], "c");
}

BOOST_AUTO_TEST_CASE(Basic)
{
  MetaInfo info;

  BOOST_CHECK_EQUAL(info.getAnnounce(), "");
  BOOST_CHECK_EQUAL(info.getName(), "");
  BOOST_CHECK_EQUAL(info.getPieceLength(), -1);
  BOOST_CHECK_EQUAL(info.getPieces().empty(), true);
  BOOST_CHECK_EQUAL(info.getFiles().empty(), true);

  info.setAnnounce("https://tracker.com/announce.php");
  BOOST_CHECK_EQUAL(info.getAnnounce(), "https://tracker.com/announce.php");

  info.setName("sample");
  BOOST_CHECK_EQUAL(info.getName(), "sample");

  info.setPieceLength(2);
  BOOST_CHECK_EQUAL(info.getPieceLength(), 2);

  std::vector<uint8_t> pieces {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A};
  info.setPieces(pieces);
  std::vector<uint8_t> pieces2 = info.getPieces();
  BOOST_REQUIRE_EQUAL_COLLECTIONS(pieces.begin(), pieces.end(),
                                  pieces2.begin(), pieces2.end());


  MetaInfo::File file1 {10, {"a", "b", "c"}};
  MetaInfo::File file2 {20, {"d", "e", "f"}};

  info.addFile(file1);
  info.addFile(file2);

  auto files = info.getFiles();
  BOOST_CHECK_EQUAL(files.size(), 2);
  BOOST_CHECK_EQUAL(files[0].length, 10);
  BOOST_CHECK_EQUAL(files[0].path[0], "a");
  BOOST_CHECK_EQUAL(files[0].path[1], "b");
  BOOST_CHECK_EQUAL(files[0].path[2], "c");
  BOOST_CHECK_EQUAL(files[1].length, 20);
  BOOST_CHECK_EQUAL(files[1].path[0], "d");
  BOOST_CHECK_EQUAL(files[1].path[1], "e");
  BOOST_CHECK_EQUAL(files[1].path[2], "f");

  bencoding::Dictionary root = info.getRoot();

  std::stringstream ss;
  root.wireEncode(ss);
  std::string result =
    "d"
      "8:announce32:https://tracker.com/announce.php"
      "4:info"
        "d"
          "5:files"
            "l"
              "d"
                "6:lengthi10e"
                "4:pathl1:a1:b1:ce"
              "e"
              "d"
                "6:lengthi20e"
                "4:pathl1:d1:e1:fe"
              "e"
            "e"
          "4:name6:sample"
          "12:piece lengthi2e"
          "6:pieces40:ABCDEFGHIJABCDEFGHIJabcdefghijabcdefghij"
        "e"
    "e";

  BOOST_CHECK_EQUAL(ss.str(), result);
}

BOOST_AUTO_TEST_CASE(EncodeDecode)
{
  MetaInfo info;

  info.setAnnounce("https://tracker.com/announce.php");
  info.setName("sample");
  info.setPieceLength(2);

  std::vector<uint8_t> pieces {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A};
  info.setPieces(pieces);

  MetaInfo::File file1 {10, {"a", "b", "c"}};
  MetaInfo::File file2 {20, {"d", "e", "f"}};

  info.addFile(file1);
  info.addFile(file2);

  std::ofstream os("tmp.torrent");
  info.wireEncode(os);
  os.close();

  std::ifstream is("tmp.torrent");
  MetaInfo info2;
  info2.wireDecode(is);

  bencoding::Dictionary root = info2.getRoot();

  std::stringstream ss;
  root.wireEncode(ss);
  std::string result =
    "d"
     "8:announce32:https://tracker.com/announce.php"
     "4:info"
      "d"
       "5:files"
        "l"
         "d"
          "6:lengthi10e"
          "4:pathl1:a1:b1:ce"
         "e"
         "d"
          "6:lengthi20e"
          "4:pathl1:d1:e1:fe"
         "e"
        "e"
       "4:name6:sample"
       "12:piece lengthi2e"
       "6:pieces40:ABCDEFGHIJABCDEFGHIJabcdefghijabcdefghij"
      "e"
    "e";

  BOOST_CHECK_EQUAL(ss.str(), result);

  boost::filesystem::path torrentPath(boost::filesystem::absolute("tmp.torrent"));
  boost::filesystem::remove(torrentPath);

}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace sbt
