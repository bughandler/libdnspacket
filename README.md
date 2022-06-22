# libdnspacket
 An ultra lightweight, cross platform and single header DNS packet parser & builder. 

+ Easy to use

+ No external dependency

+ Parse DNS packet

+ Build DNS packet

+ DNS host name compression

+ Support multiple DNS record types

  > + A
  > + NS
  > + CNAME
  > + SOA
  > + PTR
  > + MX
  > + TXT
  > + AAAA
  > + SPF



### How to use

1. Copy libdnspacket into your project folder
2. Include `libdnspacket/dns.hpp`
3. You are ready to go



### APIs

​	There are two simple APIs.

+ Parse raw DNS packet into DNS message

  ``` c++
  //
  // Parameters:
  //   buf: point to the raw DNS packet
  //   bufSize: indicate the size of [buf]
  // Return:
  //   <bool, DnsMessage>
  //   #1: indicate whether the packet was parsed successfully or not
  //   #2: when #1 value is true, this is the final structured DNS message
  //
  std::tuple<bool, DnsMessage> dns::Parse(const uint8_t* buf, size_t bufSize);
  ```

+ Build raw DNS packet from DNS message

  ``` c++
  //
  // Parameters:
  //   message: the structured DNS message
  // Return:
  //   The byte buffer of raw DNS packet
  //
  std::vector<std::byte> Build(const DnsMessage& message);
  ```

  

### Notes

+ Any feedback is welcome
