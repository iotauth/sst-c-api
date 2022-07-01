# Code Hiearchy
common -> crypto -> secure_comm -> c_api  -> test
                    load_config -----‘θ

# writing function rules

void function(return_pointer, input ...)

every return and input buffers and lengths input with pointers

void function(unsigned char * ret, unsigned int * ret_length, unsigned char * input_buf, unsigned int * input_buf_length)

# C API

**void load_config()**

- ?€λ₯? ?¨?? input?Όλ‘? ?€?΄κ°? ?΄?©?Έ sender, purpose, number of keys, crypto spec, pubkey path, privkey path ?±? ?΄?©? config ??Όλ‘? λΆλ¬?€? ??
- config ????? userκ°? ?¬?©?  ? ?κ²? ? κ³΅ν  ?? 
- ?€λ₯? ?¨??? load ?κ²λλ©? high computation, long running time?΄ λ°μ?λ―?λ‘? ?°λ‘? ?¨?λ₯? λ§λ¦
- return struct config

**void get_session_key()**
- entity clientκ°? session keyλ₯? ?»? κ³Όμ 
- input?Όλ‘λ struct config
- return struct session_key

**void secure_connection()**
- entity server?κ²? secure connection? ?κΈ°μ? κ³Όμ 
- input?Όλ‘λ port, IP address, session keyκ°? ??
- return secure socket

**void send_secure_message() **
- send secure message by encrypting with session key
- input?Όλ‘λ session key, secure socket, messageκ°? ??

**void wait_connection_message()**
- entity serverκ°? client? ?? ₯? κΈ°λ€λ¦¬λ κ³Όμ 
- input?Όλ‘λ struct config
- return struct session_key

#compile

$make
$./test
