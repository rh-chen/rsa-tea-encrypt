/*****************************************************************************
 Name        : mogucrypt.h
 Author      : sotter
 Date        : 2015年7月9日
 Description : 
 ******************************************************************************/

#ifndef MOGUCRYPT_H_
#define MOGUCRYPT_H_

#include "databuffer.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <string>

namespace cppnetwork
{

class MoguTea
{
public:
	MoguTea()
	{
		_key[0] = 0x11;
		_key[1] = 0x22;
		_key[2] = 0x33;
		_key[3] = 0x44;
		_round = 16;
	}

	virtual ~MoguTea()
	{

	}

	void setkey(uint32_t key[4]);

	bool encrypt(const void *input, int input_len, DataBuffer &out);

	bool decrypt(const void *input, int input_len, DataBuffer &out);

private:

	void tea_encrypt(uint32_t *v, uint32_t *k);

	void tea_decrypt(uint32_t *v, uint32_t *k);

	uint32_t _key[4];
	size_t _round;
};

//提供基础方法类
class MoguRSA
{
public:
#define KEY_LENGTH 1024
#define PUB_EXP    65537

	MoguRSA(const char *pubfile = NULL, const char *prifile = NULL);

	virtual ~MoguRSA();

	/*
	cnt:10 usetime:286632 average 28663us
	cnt:100 usetime:3034423 average 30344us
	cnt:1000 usetime:32080832 average 32080us
	cnt:2048 usetime:64674251 average 31579us
	*/
	//RSA性能测试数据如上，在mac本上平均生成一个需要30ms
	//自己生成private key 和public key， 结果放在_pubkey和_prikey中
	bool gen_pri_pub_key(std::string &public_key, std::string &private_key);

	//根据public key生成RSA
	bool load_from_pubkey(const char *pubkey);

	//由private key生成RSA
	bool load_from_prikey(const char *prikey);

	//从公钥文件中生成RSA
	bool load_from_pubfile(const char *file);

	//从私钥文件中生成RSA
	bool load_from_prifile(const char *file);

	/*
	cnt:10 usetime:309 average 30us
	cnt:100 usetime:2772 average 27us
	cnt:1000 usetime:29642 average 29us
	cnt:2048 usetime:58129 average 28us
	加密效率如上，加密一次30us */
	bool encrypt(const char *data, int len, DataBuffer &out);

	/*
	cnt:10 usetime:5692 average 569us
	cnt:100 usetime:54585 average 545us
	cnt:1000 usetime:543360 average 543us
	cnt:2048 usetime:1075429 average 525us
	由上可以看出，解密效率远低于加密效率，差一个数量级*/
	bool decrypt(const char *data, int len, DataBuffer &out);

	const std::string & get_pub_key()
	{
		return _pub_key;
	}

	const std::string & get_pri_key()
	{
		return _pri_key;
	}

	const std::string &get_pub_file()
	{
		return _pub_file;
	}

	const std::string &get_pri_file()
	{
		return _pri_file;
	}

private:

	//将pubkey和prikey写入到文件中
	void write_file(bool pub = true, bool pri = true);
	//将pubkey和prikey写入内存中，即_pub_key, _pri_key;
	void write_mem(bool pub = true, bool pri = true);
	//将pubkey或者prikey写入内存，此函数只能给上面的write_mem调用，主要为了避免过多的重复代码
	bool write_mem_one(bool pub);

	void error_log()
	{
		char err[128];
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		fprintf(stderr, "Error decrypting message: %s\n", err);
		ERR_free_strings();
	}

private:
	RSA *_rsa;
	std::string _pub_key;
	std::string _pri_key;
	std::string _pub_file;
	std::string _pri_file;
};

}


#endif /* MOGUCRYPT_H_ */
