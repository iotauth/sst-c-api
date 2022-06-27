#include "c_api.h"

/*
gcc -g c_common.c c_crypto.c c_secure_comm.c c_api.c -o c_api -lcrypto
*/

void load_config()
{

}


//client�� �̿���.
//config�� �ʿ��Ѱ�: IP_ADDRESS PORT_NUM sender purpose num_key


/*replyNonce[8byte]+auth_Nonce[8byte]+numkeys[4byte]+senderbuf[size:1 + buf]+purposeBuf[size:1 +buf]
//usage:    unsigned int ret_length;
            unsigned char * serialized = auth_hello_reply_message();
*/



session_key * get_session_key()
{
    int sock;
    const char * IP_ADDRESS = "127.0.0.1";
    const char * PORT_NUM = "21900";
    connect_as_client(IP_ADDRESS, PORT_NUM, &sock);

    //will be input from config.
    unsigned char sender[] = "net1.client";
    unsigned char purpose[] = "{\"group\":\"Servers\"}";
    unsigned char num_key = 3;
    const char * path_pub = "../auth_certs/Auth101EntityCert.pem";
    const char * path_priv = "../credentials/keys/net1/Net1.ClientKey.pem";    

    session_key * session_key_list = malloc(sizeof(session_key) * num_key);
    unsigned char entity_nonce[NONCE_SIZE];
    while(1)
    {

        unsigned char received_buf[1000];
        unsigned int received_buf_length = read(sock, received_buf, sizeof(received_buf));
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
        if(message_type == AUTH_HELLO)
        {
            unsigned int auth_Id;
            unsigned char auth_nonce[NONCE_SIZE];
            auth_Id = read_unsigned_int_BE(data_buf,  AUTH_ID_LEN);
            memcpy(auth_nonce, data_buf + AUTH_ID_LEN, NONCE_SIZE );
            RAND_bytes(entity_nonce, NONCE_SIZE);
            unsigned int ret_length;
            unsigned char * serialized = auth_hello_reply_message(entity_nonce, auth_nonce, num_key, sender, sizeof(sender), purpose, sizeof(purpose), &ret_length);
            
            unsigned int enc_length;
            unsigned char enc[RSA_ENCRYPT_SIGN_SIZE];
            encrypt_and_sign(serialized, ret_length, path_pub, path_priv, enc, &enc_length);
            free(serialized);

            unsigned char message[1024];
            unsigned int message_length;
            make_sender_buf(enc, enc_length, SESSION_KEY_REQ_IN_PUB_ENC, message, &message_length);
            write(sock, message, message_length);
        }
        else if(message_type == SESSION_KEY_RESP_WITH_DIST_KEY)
        {
            signed_data_t signed_data;
            distribution_key dist_key;
            unsigned int key_size = RSA_KEY_SIZE; //TODO: ??

            //parse data
            unsigned int encrypted_session_key_length = data_buf_length - (key_size * 2);
            unsigned char * encrypted_session_key = (unsigned char *)malloc(encrypted_session_key_length);
            memcpy(signed_data.data, data_buf, key_size);
            memcpy(signed_data.sign, data_buf + key_size, key_size);
            memcpy(encrypted_session_key, data_buf + key_size*2, encrypted_session_key_length);

            //verify
            SHA256_verify(signed_data.data, key_size, signed_data.sign, key_size, path_pub);
            printf("auth signature verified\n");

            //decrypt encrypted_distribution_key
            unsigned char decrypted_distribution_key[key_size]; //TODO: may need to change size. Actual decrypted_length = 56 bytes.
            unsigned int decrypted_distribution_key_length = private_decrypt(signed_data.data, key_size, RSA_PKCS1_PADDING, path_priv, decrypted_distribution_key);

            //parse decrypted_distribution_key to mac_key & cipher_key
            parse_distribution_key(&dist_key, decrypted_distribution_key, decrypted_distribution_key_length);

            //decrypt session_key with decrypted_distribution_key
            unsigned int decrypted_session_key_response_length;
            unsigned char * decrypted_session_key_response = symmetric_decrypt_authenticate(encrypted_session_key, encrypted_session_key_length, dist_key.mac_key, dist_key.mac_key_size, dist_key.cipher_key, dist_key.cipher_key_size, IV_SIZE, &decrypted_session_key_response_length);
            free(encrypted_session_key);

            //parse decrypted_session_key_response for nonce comparison & session_key.
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(decrypted_session_key_response, decrypted_session_key_response_length, reply_nonce, session_key_list);

            printf("reply_nonce in sessionKeyResp: ");
            print_buf(reply_nonce, NONCE_SIZE);
            if(strncmp(reply_nonce, entity_nonce ,NONCE_SIZE) != 0)
            { //compare generated entity's nonce & received entity's nonce.
                error_handling("auth nonce NOT verified");
            }
            else
            {
                printf("auth nonce verified!\n");
            }
            return session_key_list;
        }

    }
}

int secure_connection(session_key * s_key)
{
    //load_config
    int sock;
    const char * IP_ADDRESS = "127.0.0.1";
    const char * PORT_NUM = "21100";

    connect_as_client(IP_ADDRESS, PORT_NUM, &sock);

    unsigned char entity_nonce[HS_NONCE_SIZE];

    unsigned int parsed_buf_length;
    unsigned char * parsed_buf = parse_handshake_1(s_key, entity_nonce, &parsed_buf_length);
    unsigned char sender[128]; //TODO: actually only needs 19 bytes.
    unsigned int sender_length;
    make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_1, sender, &sender_length);
    write(sock, sender, sender_length);
    free(parsed_buf);

    //received handshake 2
    unsigned char received_buf[1000];
    unsigned int received_buf_length = read(sock, received_buf, sizeof(received_buf));
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
    if(message_type == SKEY_HANDSHAKE_2)
    {
        unsigned int parsed_buf_length;
        unsigned char * parsed_buf = check_handshake_2_send_handshake_3(data_buf, data_buf_length, entity_nonce, s_key, &parsed_buf_length);
        unsigned char sender[128]; //TODO: actually only needs 19 bytes.
        unsigned int sender_length;
        make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_3, sender, &sender_length);
        write(sock, sender, sender_length);
        free(parsed_buf);

        return sock;
    }
    
}

void send_secure_message(){}

void wait_connection_message(){}



int main()
{
    session_key * session_key_list = get_session_key();
    // print_buf(&session_key_list[0].key_id, KEY_ID_SIZE);
    // print_buf(&session_key_list[1].key_id, KEY_ID_SIZE);
    // print_buf(&session_key_list[2].key_id, KEY_ID_SIZE);
    int sock = secure_connection(&session_key_list[0]);
    printf("finished\n");
}

//session_key�� ������ �ް��;��?. struct  ����? return?'
/*
    config = load_config();
    malloc(sizeof(session_key)*numkey);
    session_key s[config.numkey];
    get_session_key(&s);
*/