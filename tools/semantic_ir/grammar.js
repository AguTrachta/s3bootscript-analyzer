/**
 * @file Parser for the S3 Boot Script binary
 * @author Agustin Trachta <agustrachta@gmail.com>
 * @license MIT
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

export default grammar({
  name: "s3boot_semantic",

  rules: {
    source_file: $ => repeat($._statement),

    _statement: $ => choice(
      $.assignment_statement,
      $.read_write_statement,
      $.poll_statement,
      $.call_statement,
      $.call_context_statement,
      $.stall_statement,
      $.info_statement,
      $.smbus_statement,
    ),

    assignment_statement: $ => seq(
      field("target", $.target),
      "<-",
      field("value", $.value),
    ),

    read_write_statement: $ => seq(
      field("target", $.target),
      "<-",
      "(",
      field("source", $.target),
      "&",
      field("data_mask", $.value),
      ")",
      "|",
      field("data", $.value),
    ),

    poll_statement: $ => seq(
      "poll",
      "until",
      "(",
      field("target", $.target),
      "&",
      field("data_mask", $.value),
      ")",
      "==",
      field("data", $.value),
    ),

    call_statement: $ => seq(
      "call",
      field("entry_point", $.value),
    ),

    call_context_statement: $ => seq(
      "call",
      field("entry_point", $.value),
      "(",
      field("context", $.value),
      ")",
    ),

    stall_statement: $ => seq(
      "stall",
      "(",
      field("duration", $.value),
      ")",
    ),

    info_statement: $ => seq(
      "info",
      "(",
      field("information", $.value),
      ")",
    ),

    smbus_statement: $ => seq(
      "smbus_execute",
      "(",
      optional($.argument_list),
      ")",
    ),

    target: $ => choice(
      $.target_mem,
      $.target_io,
      $.target_pci,
    ),

    argument_list: $ => seq(
      $.value,
      repeat(seq(",", $.value)),
    ),

    target_mem: $ => seq("mem", "[", field("address", $.address), "]"),
    target_io: $ => seq("io", "[", field("address", $.address), "]"),
    target_pci: $ => seq("pci", "[", field("address", $.pci_location), "]"),

    pci_location: $ => choice(
      $.address,
      seq(field("segment", $.address), ":", field("address", $.address)),
    ),

    address: $ => choice($.hex_number, $.meta_variable),

    value: $ => choice($.hex_number, $.meta_variable),

    hex_number: $ => /0x[0-9a-fA-F]+/,
    meta_variable: $ => /[a-zA-Z_$][a-zA-Z0-9_]*/,
  }
});
