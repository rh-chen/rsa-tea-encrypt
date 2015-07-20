/*****************************************************************************
 Name        : mogucrypt.cpp
 Author      : tianshan
 Date        : 2015年7月9日
 Description : 
 ******************************************************************************/

#include <sys/time.h>
#include "mogucrypt.h"

namespace cppnetwork
{

void MoguTea::setkey(uint32_t key[4])
{
	_key[0] = key[0];
	_key[1] = key[1];
	_key[2] = key[2];
	_key[3] = key[3];
}

void MoguTea::tea_encrypt(uint32_t* v, uint32_t* k)
{
	uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
	uint32_t delta = 0x9e3779b9;
	uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];

	for (i = 0; i < _round; i++)
	{
		sum += delta;
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
	}

	v[0] = v0;
	v[1] = v1;
}

void MoguTea::tea_decrypt(uint32_t* v, uint32_t* k)
{
	uint32_t v0 = v[0], v1 = v[1], sum, i;
	sum = (_round == 16) ? 0xE3779B90 : 0xC6EF3720;

	uint32_t delta = 0x9e3779b9;
	uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
	for (i = 0; i < _round; i++)
	{
		v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
		v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		sum -= delta;
	}

	v[0] = v0;
	v[1] = v1;
}

void showhex1(unsigned char *data, int len, const char *flag)
{
	if(data == NULL || len <= 0)
	{
		return ;
	}
	printf("%s: ", flag);
	for(int i = 0; i < len; i++)
	{
		printf("%02x ", data[i]);
	}
	printf("\n");
}

//最后不够的填充0
bool MoguTea::encrypt(const void *input, int input_len, DataBuffer &out)
{
	if(input == NULL || input_len <= 0)
		return false;

	int blocks =  (input_len + 7 ) / 8;
	//先把内存分配够，防止后面后面重复分配影响效率；
	out.expand(blocks * 8);
	out.writeBytes((const void*)input, input_len);
	int num = blocks * 8 - input_len;
	while(num--)
	{
		//后面的全部以0作为补充
		out.writeInt8(0);
	}

	uint32_t *data = (uint32_t *)out.getData();
	for(int i = 0; i < blocks; i ++)
	{
		tea_encrypt((uint32_t*)(data + 2 * i), _key);
	}

	return true;
}

bool MoguTea::decrypt(const void *input, int input_len, DataBuffer &out)
{
	if(input == NULL || input_len < 8)
		return false;

	// 只解析前面8的倍数部分
	int blocks =  input_len / 8;
	// 先把内存分配够，防止后面后面重复分配影响效率；
	out.expand(blocks * 8);
	out.writeBytes((const void*)input, blocks * 8);

	uint32_t *data = (uint32_t *)out.getData();
	for(int i = 0; i < blocks; i ++)
	{
		tea_decrypt((uint32_t*)(data + 2 * i), _key);
	}

	return true;
}

//====================== MOGU RSA ===================================
MoguRSA::MoguRSA(const char *pubfile, const char *prifile)
{
	_rsa = NULL;
	if(pubfile != NULL) _pub_file = pubfile;
	if(prifile != NULL) _pri_file = prifile;
}

MoguRSA::~MoguRSA()
{
	if(_rsa != NULL)
	{
	    RSA_free(_rsa);
	    _rsa = NULL;
	}
}

bool MoguRSA::gen_pri_pub_key(std::string &public_key, std::string &private_key)
{
	bool r = false;

	BIGNUM *bne = BN_new();
	BN_set_word(bne, RSA_F4);
	_rsa = RSA_new();

	int ret  = RSA_generate_key_ex(_rsa, KEY_LENGTH, bne, NULL);

	if(ret == 1)
	{
		write_mem();
//		write_file();
		public_key  = _pub_key;
		private_key = _pri_key;
		r = true;
	}
	else
	{
		error_log();
		RSA_free(_rsa);
		_rsa = NULL;
	}

	BN_free(bne);

	return r;
}

bool MoguRSA::load_from_pubkey(const char *pubkey)
{
	if(pubkey == NULL)
		return false;

	_pub_key = pubkey;
	BIO *bio = BIO_new(BIO_s_mem());
	BIO_write(bio, (const void*)_pub_key.c_str(), (int)_pub_key.length());
	_rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);

	if(_rsa == NULL)
	{
		error_log();
	}

	BIO_free(bio);

	return _rsa != NULL;
}

bool MoguRSA::load_from_prikey(const char *prikey)
{
	if(prikey == NULL)
		return false;

	_pri_key = prikey;
	BIO *bio = BIO_new(BIO_s_mem());

	BIO_puts(bio, prikey);
	_rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if(_rsa == NULL)
	{
		error_log();
	}

	return _rsa != NULL;
}

bool MoguRSA::load_from_pubfile(const char *file)
{
	if(file == NULL)
		return false;

	_pub_file = file;
	FILE *fp = NULL;

	if ((fp = fopen(file, "r")) == NULL)
	{
		return false;
	}

	/* 读取公钥PEM，PUBKEY格式PEM使用PEM_read_RSA_PUBKEY函数 */
	_rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
	if(_rsa == NULL)
	{
		error_log();
	}

	fclose(fp);

	return _rsa != NULL;
}

bool MoguRSA::load_from_prifile(const char *file)
{
	if(file == NULL)
		return false;

	_pri_file = file;
	FILE *fp = NULL;

	if ((fp = fopen(file, "r")) == NULL)
	{
		return false;
	}

	_rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	if(_rsa == NULL)
	{
		error_log();
	}

	fclose(fp);

	return _rsa != NULL;
}

void MoguRSA::write_file(bool pub, bool pri)
{
	if(pub && !_pub_file.empty() && _rsa != NULL)
	{
		FILE *fp = fopen(_pub_file.c_str(), "w");
		if (fp != NULL)
		{
			PEM_write_RSAPublicKey(fp, _rsa);
			fclose(fp);
		}
	}

	if(pri && !_pri_file.empty() && _rsa != NULL)
	{
		FILE *fp = fopen(_pri_file.c_str(), "w");
		if (fp != NULL)
		{
			PEM_write_RSAPrivateKey(fp, _rsa, NULL, NULL, 0, NULL, NULL);
			fclose(fp);
		}
	}
	return;
}

void MoguRSA::write_mem(bool pub, bool pri)
{
	if(pub && _pub_key.empty() && _rsa != NULL)
	{
		write_mem_one(true);
	}

	if(pri && _pri_key.empty() && _rsa != NULL)
	{
		write_mem_one(false);
	}

	return;
}

bool MoguRSA::write_mem_one(bool pub)
{
	// To get the C-string PEM form:
	BIO *bio= BIO_new(BIO_s_mem());
	if(pub)
	{
		PEM_write_bio_RSAPublicKey(bio, _rsa);
	}
	else
	{
		PEM_write_bio_RSAPrivateKey(bio, _rsa, NULL, NULL, 0, NULL, NULL);
	}

	int pub_len = BIO_pending(bio);
	char *key = (char*)malloc(pub_len + 1);
	BIO_read(bio, key, pub_len);
	key[pub_len] = '\0';

	pub ? _pub_key = key : _pri_key = key;

	free(key);
	BIO_free(bio);

	return true;
}

bool MoguRSA::encrypt(const char *data, int len, DataBuffer &out)
{
	RSA *rsa = _rsa;

	if (rsa == NULL || data == NULL || len <= 0)
		return false;

	int rsa_len = RSA_size(rsa);
	out.expand(rsa_len);

	int encry_len = RSA_public_encrypt(len, (unsigned char *) data, (unsigned char*) out.getData(), rsa,
			RSA_PKCS1_OAEP_PADDING);

	if (encry_len > 0)
	{
//		printf("encry_len = %d\n", encry_len);
		out.pourData(encry_len);
		return true;
	}
	else
	{
		error_log();
	}

	return false;
}

bool MoguRSA::decrypt(const char *data, int len, DataBuffer &out)
{
	RSA *rsa = _rsa;
	if (rsa == NULL || data == NULL || len <= 0)
		return false;

	int rsa_len = RSA_size(rsa);
	out.expand(rsa_len);

	int encry_len = RSA_private_decrypt(len, (unsigned char *) data, (unsigned char*) out.getData(), rsa,
			RSA_PKCS1_OAEP_PADDING);

	if (encry_len > 0)
	{
		out.pourData(encry_len);
		return true;
	}
	else
	{
		error_log();
	}

	return false;
}


/*======================= FOR TEST =======================*/
/*性能测试结果
run 10 use 7714 us
run 100 use 65406 us
run 1000 use 593585 us
run 10000 use 6091905 us

单次加密最大支持86个字节，很奇怪
 */
void test(int num)
{
	int cnt = num;
	char buffer[86];
	memset(buffer, 0x31, sizeof(buffer));

	struct timeval begin, end;

	MoguRSA rsa1, rsa2;
	rsa1.load_from_pubfile("pub.key");
	rsa2.load_from_prifile("pri.key");

	gettimeofday(&begin, NULL);

	while(num--)
	{
		DataBuffer encrypt;
		DataBuffer decrypt;
		rsa1.encrypt(buffer, sizeof(buffer), encrypt);
		rsa2.decrypt(encrypt.getData(), encrypt.getDataLen(), decrypt);
	}
	gettimeofday(&end, NULL);

	long use = (end.tv_sec - begin.tv_sec) * 1000 * 1000 + (end.tv_usec - begin.tv_usec);

	printf("run %d use %ld us\n", cnt, use);

	return;
}

}

//int main()
//{
//
//	MoguRSA rsa("pub.key", "pri.key"), rsa1, rsa2, rsa3, rsa4;
//	rsa.gen_pri_pub_key();
//
//	for(int i = 1, j = 1; i < 6; i ++)
//	{
//		j = j * 10;
//		test(j);
//	}
//
////	rsa1.load_from_pubkey(rsa.get_pub_key().c_str());
////	rsa2.load_from_prikey(rsa.get_pri_key().c_str());
////
////	rsa3.load_from_pubfile(rsa.get_pub_file().c_str());
////	rsa4.load_from_prifile(rsa.get_pri_file().c_str());
////
////	DataBuffer encrypt;
////	DataBuffer decrypt;
////
////	const char *str = "GOOD LUCK";
////	rsa1.encrypt(str, strlen(str), encrypt);
////	rsa2.decrypt(encrypt.getData(), encrypt.getDataLen(), decrypt);
////
////	printf("decrypt-mem:%.*s \n", decrypt.getDataLen(), decrypt.getData());
////	DataBuffer encrypt1;
////	DataBuffer decrypt1;
////	rsa3.encrypt(str, strlen(str), encrypt1);
////	rsa4.decrypt(encrypt1.getData(), encrypt1.getDataLen(), decrypt1);
////	printf("decrypt-file:%.*s \n", decrypt1.getDataLen(), decrypt1.getData());
//
//	return 0;
//}

