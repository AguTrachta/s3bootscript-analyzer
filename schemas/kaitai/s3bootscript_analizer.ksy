meta:
  id: s3_boot_script_analizer
  endian: le

seq:
  - id: records
    type: record
    repeat: eos

types:
  record:
    seq:
      - id: opcode
        type: u2
        enum: opcode_enum
      - id: length
        type: u1
      - id: body
        size: length - 3
        type:
          switch-on: opcode
          cases:
            opcode_enum::header: header
            opcode_enum::io_write: io_write
            opcode_enum::io_read_write: io_read_write
            opcode_enum::mem_write: mem_write
            opcode_enum::mem_read_write: mem_read_write    
            opcode_enum::pci_config_write: pci_config_write
            opcode_enum::pci_config_read_write: pci_config_read_write
            opcode_enum::smbus_execute: smbus_execute
            opcode_enum::stall: stall
            opcode_enum::dispatch: dispatch
            opcode_enum::dispatch_2: dispatch_2
            opcode_enum::information: information
            opcode_enum::pci_config2_write: pci_config2_write
            opcode_enum::pci_config2_read_write: pci_config2_read_write
            opcode_enum::io_poll: io_poll
            opcode_enum::mem_poll: mem_poll
            opcode_enum::pci_config_poll: pci_config_poll
            opcode_enum::pci_config2_poll: pci_config2_poll
            opcode_enum::terminate: terminate
            
  header: 
    seq:
      - id: version
        type: u2
      - id: table_length
        type: u4
      - id: reserved0
        type: u2
      - id: reserved1
        type: u2
  
  io_write:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: count
        type: u4
      - id: address
        type: u8
      - id: buffer
        size: width_size * count
        
    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
    
  io_read_write:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: address
        type: u8
      - id: data
        size: width_size
      - id: data_mask
        size: width_size

    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
        
  mem_write:
    seq:
    - id: width
      type: u4
      enum: width_enum
    - id: count
      type: u4
    - id: address
      type: u8
    - id: buffer
      size: width_size * count
      
    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
    
  mem_read_write:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: address
        type: u8
      - id: data
        size: width_size
      - id: data_mask
        size: width_size

    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
        
  pci_config_write:
    seq:
    - id: width
      type: u4
      enum: width_enum
    - id: count
      type: u4
    - id: address
      type: u8
    - id: buffer
      size: width_size * count
      
    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
          
  pci_config2_write:
    seq:
    - id: width
      type: u4
      enum: width_enum
    - id: count
      type: u4
    - id: address
      type: u8
    - id: segment
      type: u2
    - id: buffer
      size: width_size * count
      
    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
          
  pci_config_read_write:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: address
        type: u8
      - id: data
        size: width_size
      - id: data_mask
        size: width_size

    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
        
  pci_config2_read_write:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: address
        type: u8
      - id: segment
        type: u2
      - id: data
        size: width_size
      - id: data_mask
        size: width_size

    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
        
  # NOTE:
  # SmBusAddress is NOT split in the saved record. It is a packed value.
  # Its semantic subfields come from SMBUS library macros in:
  #   MdePkg/Include/Library/SmbusLib.h
  #
  # Packed meaning of SmBusAddress according to SmbusLib.h:
  #   slave_address = (SmBusAddress >> 1)  & 0x7f
  #   command       = (SmBusAddress >> 8)  & 0xff
  #   length        = (SmBusAddress >> 16) & 0x3f
  #   pec_check     = (SmBusAddress & BIT22) != 0
  #
  # For now we keep only the real serialized layout in seq.
  # Semantic decoding can be added later as derived instances if needed.
  smbus_execute:
    seq:
      - id: sm_bus_address
        type: u8
        doc: |
          Packed SMBus address value as stored by edk2.
          This field encodes slave address, command, data length, and PEC.
      - id: operation
        type: u4
        doc: SMBus operation value stored in the record.
      - id: data_size
        type: u4
        doc: Number of payload bytes stored after the fixed header.
      - id: buffer
        size: data_size
        doc: Raw SMBus payload bytes.
        
  stall:
    seq:
      - id: duration
        type: u8
        
  dispatch:
    seq:
      - id: entry_point
        type: u8
        
  dispatch_2:
    seq:
      - id: entry_point
        type: u8
      - id: context
        type: u8
        
  mem_poll:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: address
        type: u8
      - id: duration
        type: u8
      - id: loop_times
        type: u8
      - id: data
        size: width_size
      - id: data_mask
        size: width_size

    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
          
  information:
    seq:
      - id: information_length
        type: u4
      - id: information_data
        size: information_length
        
  io_poll:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: address
        type: u8
      - id: delay
        type: u8
      - id: data
        size: width_size
      - id: data_mask
        size: width_size

    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0 
          
  pci_config_poll:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: address
        type: u8
      - id: delay
        type: u8
      - id: data
        size: width_size
      - id: data_mask
        size: width_size

    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0 
          
  pci_config2_poll:
    seq:
      - id: width
        type: u4
        enum: width_enum
      - id: address
        type: u8
      - id: segment
        type: u2
      - id: delay
        type: u8
      - id: data
        size: width_size
      - id: data_mask
        size: width_size

    instances:
      width_size:
        value: |
          width == width_enum::uint8 or
          width == width_enum::fifo_uint8 or
          width == width_enum::fill_uint8 ? 1 :
          width == width_enum::uint16 or
          width == width_enum::fifo_uint16 or
          width == width_enum::fill_uint16 ? 2 :
          width == width_enum::uint32 or
          width == width_enum::fifo_uint32 or
          width == width_enum::fill_uint32 ? 4 :
          width == width_enum::uint64 or
          width == width_enum::fifo_uint64 or
          width == width_enum::fill_uint64 ? 8 :
          0
          
  terminate:
    seq: []
      
enums:
  opcode_enum:
    0x00: io_write
    0x01: io_read_write
    0x02: mem_write
    0x03: mem_read_write
    0x04: pci_config_write
    0x05: pci_config_read_write
    0x06: smbus_execute
    0x07: stall
    0x08: dispatch
    0x09: dispatch_2
    0x0a: information
    0x0b: pci_config2_write
    0x0c: pci_config2_read_write
    0x0d: io_poll
    0x0e: mem_poll
    0x0f: pci_config_poll
    0x10: pci_config2_poll
    0xaa: header
    0xff: terminate
    
  width_enum:
    0: uint8
    1: uint16
    2: uint32
    3: uint64
    4: fifo_uint8
    5: fifo_uint16
    6: fifo_uint32
    7: fifo_uint64
    8: fill_uint8
    9: fill_uint16
    10: fill_uint32
    11: fill_uint64
