# How to Run Example
Please see the instructions [here](https://github.com/iotauth/sst-c-api/blob/scenario/examples/scenario_example/README.md).

# Attack 1 - Sequenc Number

This is an example that attacks the sequence number in the original _scenario_ example code. 

The client.cpp and server.cpp files in this directory include a few lines of code detailing how the sequence number can be attacked.

This attack was successful because when the API checks if the sequence number is correct, it does this by comparing the sequence number sent by client with the sequence number sent by server. So, changing both sequence numbers allows the data to be manipulated while still passing the check. The programs' execution paths will be unchanged and they will both terminate as normal.

The comparison check is why the attack will be unsuccessful when changing only one of the values. It will result in the API throwing "ERROR: Wrong sequence number expected."

However, inserting the change inside the loops makes the attack unsuccessful, likely because of the timing between the message being sent and read. In this case, the server will throw "ERROR: Wrong sequence number expected." Because of this, a genuine replay attack may not be possible but the undetected sequence number change is still threatening.

NOTE: Changing client's `session_ctx->received_seq_num` and server's `session_ctx->sent_seq_num` will have no effect and will result in an unsuccessful attack because client only uses the `sent_seq_num` variable and server uses the `receieved_seq_num ` variable.