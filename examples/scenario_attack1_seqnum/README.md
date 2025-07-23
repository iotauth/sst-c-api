# How to Run Example
Please see the instructions [here](https://github.com/iotauth/sst-c-api/blob/scenario/examples/scenario_example/README.md).

# Sequence Number Manipulation
Here are the lines that were added to manipulate the sequence numbers and attack them:
### client.cpp
`session_ctx->sent_seq_num = -7;`

### server.cpp
`session_ctx->received_seq_num = -7;`

- Sequence numbers changed and set to be equal to pass the comparison.

## Case 1: Only client.cpp or server.cpp sequence number is changed

__Result: Unsuccessful Attack__

- server throws `"ERROR: Wrong sequence number expected."`
- The sequence numbers are not the same

## Case 2: client.cpp and server.cpp sequence numbers are both changed

__Result: Successful Attack__

- The programs terminate as normal
- When the sequence numbers are compared, they are the same.
