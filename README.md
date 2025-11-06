# ptr_checker

TODOs
- The message header is hard-coded to 16 byte long, not good!
- If a message is only as long as a message header (i.e. no payload), the library will skip the check, ignoring the posibility that a pointer is in the header. However, if the message contains a payload, the header will be checked.

please make sure the functions intended to be intercepted by LD_PRELOAD is linked dynamically. Otherwise interception will fail!
