/* Copyright (c) 2026, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file fuzz_cell.c
 * \brief Fuzz the circuit-creation and relay-message cell parsers.
 *
 * These parsers sit directly behind the ORPort: a relay or bridge feeds
 * them cell bodies supplied by an anonymous, unauthenticated peer before
 * any circuit exists.  Every other fuzzer we ship targets directory,
 * descriptor, SOCKS or HTTP input, so this is the one attacker-reachable
 * binary format that had no coverage.
 **/

#include "core/or/or.h"
#include "core/or/onion.h"
#include "core/or/relay_msg.h"

#include "core/or/cell_st.h"
#include "core/or/relay_msg_st.h"

#include "test/fuzz/fuzzing.h"

int
fuzz_init(void)
{
  return 0;
}

int
fuzz_cleanup(void)
{
  return 0;
}

/** Cell commands accepted by create_cell_parse(). */
static const uint8_t create_commands[] = {
  CELL_CREATE, CELL_CREATE_FAST, CELL_CREATE2,
};

/** Cell commands accepted by created_cell_parse(). */
static const uint8_t created_commands[] = {
  CELL_CREATED, CELL_CREATED_FAST, CELL_CREATED2,
};

/** Relay commands accepted by extend_cell_parse(). */
static const uint8_t extend_commands[] = {
  RELAY_COMMAND_EXTEND, RELAY_COMMAND_EXTEND2,
};

/** Relay commands accepted by extended_cell_parse(). */
static const uint8_t extended_commands[] = {
  RELAY_COMMAND_EXTENDED, RELAY_COMMAND_EXTENDED2,
};

/** Copy up to CELL_PAYLOAD_SIZE bytes of <b>data</b> into the payload of
 * <b>cell_out</b>, and label it with <b>command</b>.  Any remaining payload
 * bytes stay zero, exactly as they would after reading a short cell off
 * the wire. */
static void
cell_from_data(cell_t *cell_out, uint8_t command,
               const uint8_t *data, size_t sz)
{
  memset(cell_out, 0, sizeof(*cell_out));
  cell_out->circ_id = 1;
  cell_out->command = command;
  if (sz > CELL_PAYLOAD_SIZE)
    sz = CELL_PAYLOAD_SIZE;
  memcpy(cell_out->payload, data, sz);
}

int
fuzz_main(const uint8_t *data, size_t sz)
{
  /* Byte 0 picks the parser under test; byte 1 picks the cell command that
   * parser should see.  Mapping byte 1 onto the commands each parser
   * actually accepts keeps the fuzzer from wasting nearly every input on
   * the "unrecognized command" early return. */
  if (sz < 2)
    return 0;

  const uint8_t selector = data[0];
  const uint8_t which = data[1];
  data += 2;
  sz -= 2;

  cell_t cell;

  switch (selector % 5) {
    case 0: {
      create_cell_t out;
      cell_from_data(&cell, create_commands[which % ARRAY_LENGTH(
                       create_commands)], data, sz);
      if (create_cell_parse(&out, &cell) == 0)
        log_debug(LD_GENERAL, "create_cell_parse: len %u",
                  (unsigned)out.handshake_len);
      break;
    }
    case 1: {
      created_cell_t out;
      cell_from_data(&cell, created_commands[which % ARRAY_LENGTH(
                       created_commands)], data, sz);
      if (created_cell_parse(&out, &cell) == 0)
        log_debug(LD_GENERAL, "created_cell_parse: len %u",
                  (unsigned)out.handshake_len);
      break;
    }
    case 2: {
      extend_cell_t out;
      const uint8_t command =
        extend_commands[which % ARRAY_LENGTH(extend_commands)];
      if (extend_cell_parse(&out, command, data, sz) == 0)
        log_debug(LD_GENERAL, "extend_cell_parse ok");
      break;
    }
    case 3: {
      extended_cell_t out;
      const uint8_t command =
        extended_commands[which % ARRAY_LENGTH(extended_commands)];
      if (extended_cell_parse(&out, command, data, sz) == 0)
        log_debug(LD_GENERAL, "extended_cell_parse ok");
      break;
    }
    case 4: {
      /* Exercise both relay cell formats, including the variable-offset
       * v1 header, over both RELAY and RELAY_EARLY. */
      const relay_cell_fmt_t fmt =
        (which & 1) ? RELAY_CELL_FORMAT_V1 : RELAY_CELL_FORMAT_V0;
      const uint8_t command =
        (which & 2) ? CELL_RELAY_EARLY : CELL_RELAY;
      cell_from_data(&cell, command, data, sz);
      relay_msg_t *msg = relay_msg_decode_cell(fmt, &cell);
      if (msg) {
        /* Touch the decoded bounds so that a bad length or body pointer
         * shows up as an ASan read rather than passing silently. */
        log_debug(LD_GENERAL, "relay_msg_decode_cell: cmd %u len %u",
                  (unsigned)msg->command, (unsigned)msg->length);
        if (msg->length)
          log_debug(LD_GENERAL, "last byte %u",
                    (unsigned)msg->body[msg->length - 1]);
        relay_msg_free(msg);
      }
      break;
    }
  }

  return 0;
}
