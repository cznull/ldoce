// diclist6.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <stdio.h>

#include <WINSOCK2.H> 
#include <ws2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <sstream>
#include <string.h>
#include <string>
#include <assert.h>
#include <zlib.h>
#include <set>
#include <map>
#include <vector>

#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"zlib.lib")

int cmp(const char* s1, const char* s2, int nof2) {
	for (int i = 0; i < nof2; i++) {
		if (!s1[i] || s1[i] != s2[i]) {
			return 1;
		}
	}
	return 0;
}

int find(const char* text, int textlength, const char* tag, int taglength) {
	int i;
	for (i = 0; i <= textlength - taglength; i++) {
		if (!cmp(text + i, tag, taglength)) {
			return i;
		}
	}
	return -1;
}


int at16(char x) {
	if ('0' <= x && x <= '9') {
		return x - '0';
	}
	if ('a' <= x && x <= 'f') {
		return x - 'a' + 10;
	}
	if ('A' <= x && x <= 'A') {
		return x - 'A' + 10;
	}
	return 0;
}

int getline(char* s, int length, std::vector<std::string>& line) {
	int cur, next;
	cur = 0;
	next = find(s + cur, length - cur, "\r\n", 2);
	while (next >= 0) {
		if (next > 0) {
			//int i;
			//for (i = 0; i < next&&s[cur+i]=='/'; i++);
			//if (next > i) {
			line.push_back(std::string(s + cur, next));
			//}
		}
		cur += next + 2;
		next = find(s + cur, length - cur, "\r\n", 2);
	}
	if (length > cur) {
		line.push_back(std::string(s + cur, length - cur));
	}
	return 0;
}

SSL* sslinit(const char* host,SSL_CTX *(&ctx), SOCKET &client) {

	int ret;

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	const SSL_METHOD* meth = SSLv23_client_method();
	//SSL_CTX* ctx;
	ctx = SSL_CTX_new(meth);
	if (ctx == NULL)
	{
		std::cout << "SSL_CTX_new error\n";
		return 0;
	}


	//int timeout = 300;
	//ret = setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (char*)& timeout, sizeof(timeout));


	unsigned short port = 443;

	//hostent* ip = gethostbyname(host);

	//if (!ip) {
	//	std::cout << "host error\n";
	//	return -1;
	//}

	addrinfo* res;
	addrinfo hints = { 0 };
	//hints.ai_flags = AI_PASSIVE;
	//hints.ai_family = AF_INET;
	//hints.ai_socktype = SOCK_STREAM;
	int err;
	if ((err = getaddrinfo(host, "https", &hints, &res)) != 0) {
		printf("error %d : %s\n", err, gai_strerror(err));
		return 0;
	}
	//sockaddr_in sin;
	//sin.sin_family = AF_INET; 
	//sin.sin_port = htons(port);
	//sin.sin_addr = res->ai;

	client = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	if (client == INVALID_SOCKET)
	{
		std::cout << "socket error\n";
		return 0;
	}

	ret = connect(client, res->ai_addr, res->ai_addrlen);
	if (ret == SOCKET_ERROR)
	{

		std::cout << WSAGetLastError() << "connect error 1\n";
		return 0;
	}

	SSL* ssl = SSL_new(ctx);
	if (ssl == NULL)
	{
		std::cout << "SSL NEW error\n";
		return 0;
	}

	SSL_set_fd(ssl, client);
	ret = SSL_connect(ssl);
	if (ret == -1)
	{
		std::cout << "SSL ACCEPT error\n";
		return 0;
	}

	return ssl;
}


int get(const char* host, const char* url, int m, char* rec, char* rec1, const char* cookie, int& length,SSL *ssl) {
	int ret;

	std::stringstream stream;
	stream << "GET " << url << " HTTP/1.1\r\n";
	stream << "Host: " << host << "\r\n";
	stream << "Connection: keep-alive\r\n";
	stream << "Upgrade-Insecure-Requests: 1\r\n";
	stream << "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36\r\n";
	stream << "DNT: 1\r\n";
	stream << "Accept: */*\r\n";
	stream << "Accept-Language: zh-Hans-CN, zh-Hans; q=0.8, en-US; q=0.5, en; q=0.3\r\n";
	//stream << "Connection: Keep-Alive\r\n";
	//stream << "Origin: https://www.bilibili.com\r\n";
	stream << "Accept-Encoding: deflate\r\n";
	if (cookie) {
		stream << "Cookie: " << cookie << "\r\n";
	}
	stream << "\r\n";

	std::string s = stream.str();
	const char* sendData = s.c_str();
	ret = SSL_write(ssl, sendData, strlen(sendData));
	if (ret == -1)
	{
		std::cout << "SSL write error !\n";
		return -1;
	}

	int start = 0;
	int pos, headp=0, sizep, datap, endp, flag = 0;
	int chunksize = 0;
	int i;
	rec[0] = 0x78;
	rec[1] = 0x01;
	rec += 2;
	while (start < m - 1024 && (ret = SSL_read(ssl, rec + start, 1024)) > 0)
	{
		start += ret;
		headp = find(rec, start, "\r\n\r\n", 4);
		if (headp > 0) {
			break;
		}
	}
	rec[headp] = 0;

	std::cout << rec; 
	pos = find(rec, headp, "Content-Length:", strlen("Content-Length:"));
	if (pos > 0) {
		return 0;
		sscanf(rec + pos + strlen("Content-Length:"), "%d", &chunksize);
		for (i = 0; i < start - 4 - headp; i++) {
			rec[i] = rec[i + headp + 4];
		}
		start -= headp + 4;
		while (start < m - 1024 && (ret = SSL_read(ssl, rec + start, 1024)) > 0)
		{
			start += ret;
			if (start >= chunksize) {
				break;
			}
		}
		rec[start] = 0;
		//SSL_shutdown(ssl);
		//SSL_free(ssl);
		//SSL_CTX_free(ctx);

		//closesocket(client);
		//WSACleanup();
		length = start;
		return 0;
	}
	for (i = 0; i < start - 4 - headp; i++) {
		rec[i] = rec[i + headp + 4];
	}
	start -= headp + 4;

	endp = 0;
	ret = 0;
	do {
		start += ret;
	st:
		if (flag) {
			if (start > endp + chunksize) {
				for (i = 0; i < start - endp - chunksize - 2; i++) {
					rec[endp + i + chunksize] = rec[endp + i + chunksize + 2];
				}
				start -= 2;
				endp += chunksize;
				flag = 0;
				goto st;
			}
		}
		else {
			sizep = find(rec + endp, start - endp, "\r\n", 2);
			if (sizep > 0) {
				if (sizep == 1 && rec[endp] == '0') {
					start = endp;
					break;
				}
				chunksize = 0;
				for (i = 0; i < sizep; i++) {
					chunksize = chunksize * 16 + at16(rec[endp + i]);
				}
				for (i = 0; i < start - endp - sizep - 2; i++) {
					rec[endp + i] = rec[endp + i + sizep + 2];
				}
				start -= sizep + 2;
				flag = 1;
				goto st;
			}
		}
	} while (start < m - 1024 && (ret = SSL_read(ssl, rec + start, 1024)) > 0);

	/*while (start < m - 1024 && (ret = SSL_read(ssl, rec + start, 1024)) > 0)
	{
		start += ret;
	}*/
	rec[start] = 0;
	rec -= 2;
	start += 2;
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	ret = inflateInit(&strm);
	strm.avail_in = start;
	strm.next_in = (unsigned char*)rec;
	strm.avail_out = m;
	strm.next_out = (unsigned char*)rec1;
	start = m - inflate(&strm, Z_NO_FLUSH);
	inflateEnd(&strm);
	rec1[strm.total_out] = 0;

	//SSL_shutdown(ssl);
	//SSL_free(ssl);
	//SSL_CTX_free(ctx);

	//closesocket(client);
	return 0;
}

int getcon(const char* rec, int l, std::string& s, const char* target, int length) {
	int pos;
	int domc;
	pos = find(rec, l, target, length);
	s.clear();
	if (pos >= 0) {
		pos += length;
		for (domc = 1; domc > 0 && pos < l;) {
			if (rec[pos] == '<') {
				pos++;
				if (pos < l) {
					if (rec[pos] == '/') {
						domc--;
					}
					else {
						domc++;
					}
					for (; pos < l && rec[pos] != '>'; pos++);
					pos++;
				}
			}
			else {
				s.push_back(rec[pos]);
				pos++;
			}
		}
		return 0;
	}
	return -1;
}

int gettarget(const char* rec, int l,const char *name,int namelength, std::string& s) {
	int pos;
	int domc;
	pos = find(rec, l, name, namelength);
	if (pos >= 0) {
		s = std::string(rec + pos, namelength);
		pos += namelength;
		for (domc = 1; domc > 0 && pos < l;) {
			if (rec[pos] == '<') {
				s.push_back(rec[pos]);
				pos++;
				if (pos < l) {
					if (rec[pos] == '/') {
						domc--;
					}
					else {
						domc++;
					}
					for (; pos < l && rec[pos] != '>'; pos++) {
						s.push_back(rec[pos]);
					}
					if (pos < l) {
						s.push_back(rec[pos]);
						pos++;
					}
				}
			}
			else {
				s.push_back(rec[pos]);
				pos++;
			}
		}
		return pos;
	}
	s = std::string();
	return -1;
}

int gett(const char* rec, int l, std::string& all, std::string& name) {
	int pos;
	pos = find(rec, l, " ", 1);
	if (pos > 0) {
		name = std::string(rec + 1, pos - 1);
	}
	pos = find(rec, l, ">", 1);
	if (pos > 0) {
		all = std::string(rec, pos + 1);
	}
	return pos+1;
}

int isreserve(std::vector<std::string> tree) {
	//return 1;
	if (tree.size() == 0) {
		return 0;
	}
	if (tree[tree.size() - 1] == "<script type='text/javascript'>") {
		return 0;
	}
	if (tree[tree.size() - 1] == "<span class=\"ACTIV\">") {
		return 0;
	}
	if (tree[tree.size() - 1] == "<span class=\"FIELD\">") {
		return 0;
	}
	if (tree[tree.size() - 1] == "<span class=\"SIGNPOST\">") {
		return 0;
	}
	if (find(tree[tree.size() - 1].c_str(), tree[tree.size() - 1].length(), "data-src-mp3", strlen("data-src-mp3")) > 0) {
		return 0;
	}
	for (int i = 0; i < tree.size(); i++) {
		if (tree[i] == "<span class=\"Thesref\">"|| tree[i] == "<span class=\"SYN\">" || tree[i] == "<span class=\"OPP\">") {
			return 0;
		}
	}
	return 1;
}

int reduce(std::string &in, std::string &out) {
	int pos=0;
	int domc;
	int reserve = 1;
	std::string name;
	std::string all;
	std::vector<std::string> tree;
	std::vector<std::string> nametree;
	out.clear();
	pos += gett(in.c_str() + pos, in.length() - pos, all, name);
	nametree.push_back(name);
	tree.push_back(all);

	if (name != "img" && name != "a") {
		out = out + all;
	}
	for (domc = 1; domc > 0 && pos < in.length();) {
		if (in[pos] == '<') {
			if (pos < in.length() && in[pos+1] == '/') {
				pos += gett(in.c_str() + pos, in.length() - pos, all, name);
				if (nametree[nametree.size() - 1] != "img" && nametree[nametree.size() - 1] != "a" && reserve) {
					out = out + all;
				}
				nametree.pop_back();
				tree.pop_back();
				reserve = isreserve(tree);
			}
			else {
				pos += gett(in.c_str() + pos, in.length() - pos, all, name);
				nametree.push_back(name);
				tree.push_back(all);
				reserve = isreserve(tree);
				if (nametree[nametree.size() - 1] != "img" && nametree[nametree.size() - 1] != "a" && reserve) {
					out = out + all;
				}
			}
		}
		else {
			if (reserve) {
				out.push_back(in[pos]);
			}
			pos++;
		}
	}
	return pos;
}

int main()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		return -1;
	}

	FILE* fi, * fiout, * fitemp;
	char* ficon;
	int ficount;
	char* rec = new char[1048576];
	char* rec1 = new char[1048576];
	int count, i, j, pos, next, a, c, l;
	SSL* ssl;
	SSL_CTX* ctx;
	SOCKET client;
	ssl = sslinit("nga.178.com", ctx, client);
	if (!fopen_s(&fi, "D:/files/courses/en/list6.txt", "rb")) {

		fseek(fi, 0, SEEK_END);
		ficount = ftell(fi);
		fseek(fi, 0, SEEK_SET);
		ficon = (char*)malloc(ficount * sizeof(char));
		ficount = fread(ficon, 1, ficount, fi);
		fclose(fi);
		if (!fopen_s(&fiout, "D:/files/courses/en/list6_.html", "wb")) {

			fwrite(
				"<html>"
				"<head>"
				"<style>"
				".spon{font-family:cambria;font-size:15px;margin-left:5px;}"
				".word{font-family:arial;font-size:15px;color:#cc0000;font-weight:bold;}"
				".DEF{color:#000099}"
				"body{font-family: arial;font-size:12px;}"
				//".DEF{display: block;}"
				".EXAMPLE{display:block;margin-left:12px;}"
				".ColloExa{display:block;margin-left:12px;}"
				".COLLO{font-weight:bold;}"
				".GRAM{color:#009900;}"
				".pos{color:#009900;}"
				".GramExa{display:block;margin-left:12px;}"
				".PROPFORM{font-weight:bold;}"
				".PROPFORMPREP{font-weight:bold;}"
				".Sense{display:block;margin-left:15px;margin-bottom:9px;}"
				".section{margin-left:10%;margin-right:10%;line-height:1.4em;}"
				"</style>"
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />"
				"</head><body>",1,665,fiout);

			std::vector<std::string> line;
			getline(ficon, ficount, line);
			for (i = 0; i < line.size(); i++) {

				rec[0] = 0;
				if (!fopen_s(&fitemp, ("D:/files/courses/en/ldoce/" + line[i] + ".txt").c_str(), "rb")) {
					j = fread(rec, 1, 1048576, fitemp);
					rec[j] = 0;
					fclose(fitemp);
				}
				else {
					int flag = get("www.ldoceonline.com", ("/dictionary/" + line[i]).c_str(), 1048576, rec, rec1, nullptr, l, ssl);
					if (flag) {

						SSL_shutdown(ssl);
						SSL_free(ssl);
						SSL_CTX_free(ctx);
						closesocket(client);
						ssl = sslinit("www.ldoceonline.com", ctx, client);
					}
					if (strlen(rec) > 10) {
						if (!fopen_s(&fitemp, ("D:/files/courses/en/ldoce/" + line[i] + ".txt").c_str(), "wb")) {
							fwrite(rec, 1, strlen(rec), fitemp);
							fclose(fitemp);
						}
					}
				}
				std::string spon,s;
				std::string s0,s1,s2;

				if (find(rec, strlen(rec), "Core vocabulary: M", 18) < 0 && find(rec, strlen(rec), "Core vocabulary: H", 18) < 0) {
					continue;
				}
				//getcon(rec, strlen(rec), spon, "<span class=\"PRON\">", strlen("<span class=\"PRON\">"));
				if (spon.length()) {

				}
				else {
					std::cout << '\n' << line[i];
				}
				int end;
				end = find(rec, strlen(rec), "End of DIV entry_content", 24);
				fprintf(fiout, "<div class=\"section\"><span class=\"word\">%s</span>", line[i].c_str());
				int entrycur = 0, entrynext = 0;
				entrynext = gettarget(rec + entrycur, end - entrycur, "<span class=\"ldoceEntry Entry\"", 30, s0);
				while (entrynext > 0) {
					getcon(s0.c_str(), s0.length(), spon, "<span class=\"PRON\">", strlen("<span class=\"PRON\">"));
					getcon(s0.c_str(), s0.length(), s, "<span class=\"POS\">", strlen("<span class=\"POS\">"));
					if (spon.length()) {
						fprintf(fiout, "<span class=\"spon\">/%s/</span>", spon.c_str());
					}
					fprintf(fiout, "<span class=\"pos\">%s</span>",  s.c_str());
					int curpos = 0;
					int next = 0;
					next = gettarget(s0.c_str() + curpos, s0.length() - curpos, "<span class=\"Sense\"", 19, s1);
					while (next > 0) {
						reduce(s1, s2);
						fprintf(fiout, "%s", s2.c_str());
						curpos += next;
						next = gettarget(s0.c_str() + curpos, s0.length() - curpos, "<span class=\"Sense\"", 19, s1);
					}
					entrycur += entrynext;
					entrynext = gettarget(rec + entrycur, end - entrycur, "<span class=\"ldoceEntry Entry\"", 30, s0);
				}
				fprintf(fiout, "</div>");
			}
			fprintf(fiout, "</body></html>");
			fclose(fiout);
		}
		free(ficon);
	}

	WSACleanup();
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
