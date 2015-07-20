/*****************************************************************************
Name        : test_mogucrypt.cpp
Author      : tianshan
Date        : 2015年7月14日
Description : 
******************************************************************************/
#include "mogucrypt.h"
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

using namespace cppnetwork;

void show_hex(const char *data, int len, const char *str)
{
	unsigned char *d = (unsigned char*)data;
	if(str != NULL)
		printf("%s:", str);
	for(int i = 0; i < len; i++)
	{
		printf("%02x ", d[i]);
	}

	printf("\n");

	return;
}


void test_rsa_fun(int cnt)
{
	if(cnt > 2048)
		cnt = 2048;

	int num = cnt;
	MoguRSA rsa;
	string public_key, private_key;
	rsa.gen_pri_pub_key(public_key, private_key);

//	printf("private key:%s \n", private_key.c_str());

	char buffer[80];
	DataBuffer encrypt_buffer, decrypt_buffer;
	rsa.encrypt(buffer, 80, encrypt_buffer);

	struct timeval begin, end;
	MoguRSA rsa1;
	gettimeofday(&begin, NULL);
	while (num--)
	{
		rsa1.load_from_prikey(private_key.c_str());
		rsa1.decrypt(encrypt_buffer.getData(), encrypt_buffer.getDataLen(), decrypt_buffer);
		decrypt_buffer.clear();
	}

	gettimeofday(&end, NULL);

	long time = (end.tv_sec - begin.tv_sec) * 1000 * 1000  + (end.tv_usec - begin.tv_usec);

	printf("cnt:%d usetime:%ld average %ldus\n", cnt, time, (time/cnt));

	return;
}

void test_tea()
{
	MoguTea tea;
	uint32_t key[4] = {0x11, 0x22, 0x33, 0x44};
	char data[] = "012345678901234567890123456789012345678901234567890123456789";
	DataBuffer encrypt_data, decrypt_data;

	tea.setkey(key);

	show_hex(data, strlen(data), "before tea");
	tea.encrypt(data, strlen(data), encrypt_data);
	show_hex(encrypt_data.getData(), encrypt_data.getDataLen(), "after tea");
	tea.decrypt(encrypt_data.getData(), encrypt_data.getDataLen(), decrypt_data);
	show_hex(decrypt_data.getData(), decrypt_data.getDataLen(), "decrypt tea");

	return ;
}

int main()
{
//	int array[] = {10, 100, 1000, 10000};
//
//	for(int i = 0; i < (sizeof(array) / sizeof(int)); i++)
//	{
//		test_fun(array[i]);
//	}

	test_tea();
	return 0;
}



