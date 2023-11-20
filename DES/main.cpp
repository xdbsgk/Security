#include <iostream>
#include <cstring>
#include "BlockCipherMode.h"
#define BLOCK_MODE 4    /* 0: DES, 1: CBC, 2: CFB, 3: OFB, 4: CTR */

using namespace std;

int main() {
    int i;

    BYTE p_text[128] = {0, };
    BYTE key[9] = {0, };
    BYTE IV[9] = {0, };
    BYTE c_text[128] = {0, };
    BYTE d_text[128] = {0, };
    int msg_len; int block_cnt=0;
    UINT64 ctr = 0;

    /* 평문 입력 */
    cout << "평문 입력: ";
    cin.getline((char*)p_text, 128);

    /* 비밀키 입력 */
    cout << "비밀키 입력: ";
    cin.getline((char*)key, 9);

    if(BLOCK_MODE!=4) {
        /* 초기화 벡터 입력 */
        cout << "초기화 벡터 입력: ";
        cin.getline((char*)IV, 9);
    } else {
        /* 카운터 입력 */
        cout << "ctr 입력: ";
        cin >> ctr;
    }

    // Mode 출력
    cout << "\n[Mode: " << BLOCK_MODE << "]\n";

    
    /* 메시지 길이 계산 */
    // block_count = (msg_len%BLOCK_SIZE) ? (msg_len/BLOCK_SIZE+1) : (msg_len/BLOCK_SIZE);
    msg_len = (strlen((char *)p_text) % BLOCK_SIZE) ? ((strlen((char *)p_text) / BLOCK_SIZE + 1) * 8) : strlen((char *)p_text);

    /* 암호화 */
    if (BLOCK_MODE==0) {                                    // PPT DES 암호화
        for (i=0; i<block_cnt; i++) {
            DES_Encryption(&p_text[i*BLOCK_SIZE], &c_text[i*BLOCK_SIZE], key);
        }
    } else if (BLOCK_MODE==1) {
        DES_CBC_Enc(p_text, c_text, IV, key, msg_len);      // DES-CBC 암호화
    } else if (BLOCK_MODE==2) { 
        DES_CFB_Enc(p_text, c_text, IV, key, msg_len);      // DES-CFB 암호화
    } else if (BLOCK_MODE==3) {
        DES_OFB_Enc(p_text, c_text, IV, key, msg_len);      // DES-OFB 암호화
    } else {
        DES_CTR_Enc(p_text, c_text, key, ctr, msg_len);     // DES-CTR 암호화
    }


    /* 암호문 출력 */
    cout << "\n암호문: ";
    for (i=0; i<msg_len; i++) {
        printf("%c", c_text[i]);
    } cout << endl;

    /* 복호화 */
    if (BLOCK_MODE==0) {                                    // PPR DES 복호화
        for (i=0; i<block_cnt; i++) {
            DES_Decryption(&c_text[i*BLOCK_SIZE], &d_text[i*BLOCK_SIZE], key);      
        }
    } else if (BLOCK_MODE==1) {
        DES_CBC_Dec(c_text, d_text, IV, key, msg_len);      // DES-CBC 복호화
    } else if (BLOCK_MODE==2) {
        DES_CFB_Dec(c_text, d_text, IV, key, msg_len);      // DES-CFB 복호화
    } else if (BLOCK_MODE==3) {
        DES_OFB_Dec(c_text, d_text, IV, key, msg_len);      // DES-CFB 복호화
    } else {
        DES_CTR_Dec(c_text, d_text, key, ctr, msg_len);     // DES-CTR 복호화
    }

    /* 복호문 출력 */
    cout << "\n복호문: ";
    for(i=0; i<msg_len; i++) {
        printf("%c", d_text[i]); 
    } cout << endl << endl;

    return 0;
}
