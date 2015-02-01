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

#include "msg/msg-base.hpp"

#include "boost-test.hpp"

namespace sbt {
namespace msg {
namespace test {

BOOST_AUTO_TEST_SUITE(TestMsgBase)

class TestMsg : public MsgBase
{
public:
  TestMsg()
  {
  }

  TestMsg(uint8_t id, ConstBufferPtr payload)
    : MsgBase(id, payload)
  {
  }

private:
  virtual void
  encodePayload()
  {
  }

  virtual void
  decodePayload()
  {
  }
};

BOOST_AUTO_TEST_CASE(Encode)
{
  ConstBufferPtr payload = std::make_shared<Buffer>(20, 1);
  uint8_t id = 2;

  uint8_t encoded_raw[] = {
    0x00, 0x00, 0x00, 0x15,
    0x02,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
  };

  TestMsg msg(id, payload);

  ConstBufferPtr encoded = msg.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->buf(), encoded->buf() + encoded->size(),
                                  encoded_raw, encoded_raw + sizeof(encoded_raw));
}

BOOST_AUTO_TEST_CASE(Decode)
{
  ConstBufferPtr payload = std::make_shared<Buffer>(20, 1);
  uint8_t id = 2;

  uint8_t encoded_raw[] = {
    0x00, 0x00, 0x00, 0x15,
    0x02,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
  };

  auto encoded = std::make_shared<Buffer>(encoded_raw, sizeof(encoded_raw));

  TestMsg msg;

  BOOST_REQUIRE_NO_THROW(msg.decode(encoded));

  BOOST_CHECK_EQUAL(msg.getId(), id);
  BOOST_CHECK_EQUAL_COLLECTIONS(msg.getPayload()->begin(), msg.getPayload()->end(),
                                payload->begin(), payload->end());
}

BOOST_AUTO_TEST_CASE(TestKeepAlive)
{
  uint8_t encoded_keep_alive[] = {
    0x00, 0x00, 0x00, 0x00
  };

  KeepAlive keepAlive;

  ConstBufferPtr encoded = keepAlive.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_keep_alive,
                                  encoded_keep_alive + sizeof(encoded_keep_alive));


  KeepAlive keepAlive2;
  BOOST_REQUIRE_NO_THROW(keepAlive2.decode(encoded));

  BOOST_CHECK_EQUAL(keepAlive2.getId(), MSG_ID_KEEP_ALIVE);
  BOOST_CHECK_EQUAL(static_cast<bool>(keepAlive2.getPayload()), false);
}

BOOST_AUTO_TEST_CASE(TestChoke)
{
  uint8_t encoded_choke[] = {
    0x00, 0x00, 0x00, 0x01,
    0x00
  };

  Choke choke;

  ConstBufferPtr encoded = choke.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_choke,
                                  encoded_choke + sizeof(encoded_choke));

  Choke choke2;
  BOOST_REQUIRE_NO_THROW(choke2.decode(encoded));

  BOOST_CHECK_EQUAL(choke2.getId(), MSG_ID_CHOKE);
  BOOST_CHECK_EQUAL(static_cast<bool>(choke2.getPayload()), false);
}

BOOST_AUTO_TEST_CASE(TestUnchoke)
{
  uint8_t encoded_unchoke[] = {
    0x00, 0x00, 0x00, 0x01,
    0x01
  };

  Unchoke unchoke;

  ConstBufferPtr encoded = unchoke.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_unchoke,
                                  encoded_unchoke + sizeof(encoded_unchoke));


  Unchoke unchoke2;
  BOOST_REQUIRE_NO_THROW(unchoke2.decode(encoded));

  BOOST_CHECK_EQUAL(unchoke2.getId(), MSG_ID_UNCHOKE);
  BOOST_CHECK_EQUAL(static_cast<bool>(unchoke2.getPayload()), false);
}

BOOST_AUTO_TEST_CASE(TestInterested)
{
  uint8_t encoded_interested[] = {
    0x00, 0x00, 0x00, 0x01,
    0x02
  };

  Interested interested;

  ConstBufferPtr encoded = interested.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_interested,
                                  encoded_interested + sizeof(encoded_interested));


  Interested interested2;
  BOOST_REQUIRE_NO_THROW(interested2.decode(encoded));

  BOOST_CHECK_EQUAL(interested2.getId(), MSG_ID_INTERESTED);
  BOOST_CHECK_EQUAL(static_cast<bool>(interested2.getPayload()), false);
}

BOOST_AUTO_TEST_CASE(TestNotInterested)
{
  uint8_t encoded_not_interested[] = {
    0x00, 0x00, 0x00, 0x01,
    0x03
  };

  NotInterested notInterested;

  ConstBufferPtr encoded = notInterested.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_not_interested,
                                  encoded_not_interested + sizeof(encoded_not_interested));


  Interested notInterested2;
  BOOST_REQUIRE_NO_THROW(notInterested2.decode(encoded));

  BOOST_CHECK_EQUAL(notInterested2.getId(), MSG_ID_NOT_INTERESTED);
  BOOST_CHECK_EQUAL(static_cast<bool>(notInterested2.getPayload()), false);
}

BOOST_AUTO_TEST_CASE(TestHave)
{
  uint8_t encoded_have[] = {
    0x00, 0x00, 0x00, 0x05,
    0x04,
    0x00, 0x00, 0x01, 0x00
  };

  Have have(256);

  ConstBufferPtr encoded = have.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_have,
                                  encoded_have + sizeof(encoded_have));


  Have have2;
  BOOST_REQUIRE_NO_THROW(have2.decode(encoded));

  BOOST_CHECK_EQUAL(have2.getId(), MSG_ID_HAVE);
  BOOST_CHECK_EQUAL(static_cast<bool>(have2.getPayload()), true);
  BOOST_CHECK_EQUAL(have2.getIndex(), 256);
}

BOOST_AUTO_TEST_CASE(TestBitfield)
{
  uint8_t encoded_bitfield[] = {
    0x00, 0x00, 0x00, 0x0d,
    0x05,
    0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x01, 0x02
  };

  uint8_t bitfield_raw[] = {
    0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x01, 0x02
  };

  Bitfield bitfield(make_shared<Buffer>(bitfield_raw, sizeof(bitfield_raw)));

  ConstBufferPtr encoded = bitfield.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_bitfield,
                                  encoded_bitfield + sizeof(encoded_bitfield));


  Bitfield bitfield2;
  BOOST_REQUIRE_NO_THROW(bitfield2.decode(encoded));

  BOOST_CHECK_EQUAL(bitfield2.getId(), MSG_ID_BITFIELD);
  BOOST_CHECK_EQUAL(static_cast<bool>(bitfield2.getPayload()), true);
  BOOST_REQUIRE_EQUAL_COLLECTIONS(bitfield2.getBitfield()->begin(),
                                  bitfield2.getBitfield()->end(),
                                  bitfield_raw,
                                  bitfield_raw + sizeof(bitfield_raw));
}

BOOST_AUTO_TEST_CASE(TestRequest)
{
  uint8_t encoded_request[] = {
    0x00, 0x00, 0x00, 0x0d,
    0x06,
    0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x01, 0x02
  };

  Request request(256, 257, 258);

  ConstBufferPtr encoded = request.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_request,
                                  encoded_request + sizeof(encoded_request));


  Request request2;
  BOOST_REQUIRE_NO_THROW(request2.decode(encoded));

  BOOST_CHECK_EQUAL(request2.getId(), MSG_ID_REQUEST);
  BOOST_CHECK_EQUAL(static_cast<bool>(request2.getPayload()), true);
  BOOST_CHECK_EQUAL(request2.getIndex(), 256);
  BOOST_CHECK_EQUAL(request2.getBegin(), 257);
  BOOST_CHECK_EQUAL(request2.getLength(), 258);
}

BOOST_AUTO_TEST_CASE(TestPiece)
{
  uint8_t encoded_piece[] = {
    0x00, 0x00, 0x00, 0x0d,
    0x07,
    0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x01, 0x02
  };

  uint8_t block_raw[] = {
    0x00, 0x00, 0x01, 0x02
  };

  Piece piece(256, 257, make_shared<Buffer>(block_raw, sizeof(block_raw)));

  ConstBufferPtr encoded = piece.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_piece,
                                  encoded_piece + sizeof(encoded_piece));


  Piece piece2;
  BOOST_REQUIRE_NO_THROW(piece2.decode(encoded));

  BOOST_CHECK_EQUAL(piece2.getId(), MSG_ID_PIECE);
  BOOST_CHECK_EQUAL(static_cast<bool>(piece2.getPayload()), true);
  BOOST_CHECK_EQUAL(piece2.getIndex(), 256);
  BOOST_CHECK_EQUAL(piece2.getBegin(), 257);
  BOOST_REQUIRE_EQUAL_COLLECTIONS(piece2.getBlock()->begin(),
                                  piece2.getBlock()->end(),
                                  block_raw,
                                  block_raw + sizeof(block_raw));
}

BOOST_AUTO_TEST_CASE(TestCancel)
{
  uint8_t encoded_cancel[] = {
    0x00, 0x00, 0x00, 0x0d,
    0x08,
    0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x01, 0x02
  };

  Cancel cancel(256, 257, 258);

  ConstBufferPtr encoded = cancel.encode();

  BOOST_REQUIRE_EQUAL_COLLECTIONS(encoded->begin(),
                                  encoded->end(),
                                  encoded_cancel,
                                  encoded_cancel + sizeof(encoded_cancel));


  Cancel cancel2;
  BOOST_REQUIRE_NO_THROW(cancel2.decode(encoded));

  BOOST_CHECK_EQUAL(cancel2.getId(), MSG_ID_CANCEL);
  BOOST_CHECK_EQUAL(static_cast<bool>(cancel2.getPayload()), true);
  BOOST_CHECK_EQUAL(cancel2.getIndex(), 256);
  BOOST_CHECK_EQUAL(cancel2.getBegin(), 257);
  BOOST_CHECK_EQUAL(cancel2.getLength(), 258);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace msg
} // namespace sbt
