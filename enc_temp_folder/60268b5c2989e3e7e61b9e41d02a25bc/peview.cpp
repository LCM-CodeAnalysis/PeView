#include <iostream>
#include <cstdio>
#include <stdlib.h>

#define BUFFER_SIZE 16

using namespace std;

bool CheckSignature(FILE* fp);
void CheckBit(FILE* fp);
void ViewMenu(FILE* fp);
void selectMenu(int menuOption, FILE* fp);
void ViewHex_32(FILE* fp);
//void ViewPE_32(FILE* fp);
//void ViewHex_64(FILE* fp);
//void ViewPE_64(FILE* fp);

bool x32Flag = false;
unsigned int importTableRVA = 0, importTableSize = 0, sectionRVA = 0, sectionRAW = 0;

int main() {
	char filePath[_MAX_PATH];

	cout << "파일경로를 입력해주세요. :";
	cin >> filePath;
	FILE* fp = fopen(filePath, "rb");
	
	if (CheckSignature(fp)) {
		CheckBit(fp);
		ViewMenu(fp);
	}
}

bool CheckSignature(FILE* fp) {
	char signature[3];
	fseek(fp, 0, SEEK_SET);
	fread(signature, 2, 1, fp);
	if (strcmp(signature, "MZ")) {
		return true;
	}
	else {
		cout << "파일의 형식이 올바르지 않습니다.";
		return false;
	}
}

void CheckBit(FILE* fp) {
	char temp[4];
	long long_image_nt_header_start_offset;
	unsigned char machine[5];
	fseek(fp, 0x3c, SEEK_SET);
	fread(temp, 4, 1, fp);
	long_image_nt_header_start_offset = (temp[3] & 0xFF) * (16 ^ 6) + (temp[2] & 0xFF)* (16 ^ 4) + (temp[1] & 0xFF)* (16 ^ 2) + (temp[0] & 0xFF);
	fseek(fp, long_image_nt_header_start_offset + 4, SEEK_SET);
	fread(temp, 2, 1, fp);
	if ((temp[1] & 0xFF) == 1 && (temp[0] & 0xFF) == 76) {
		x32Flag = true;
	}
	else {
		x32Flag = false;
	}
}

void ViewMenu(FILE* fp) {
	int menuOption = 0;

	cout << endl << "----------Menu----------" << endl;
	cout << "0. View Hex" << endl;
	cout << "1. View PE" << endl;
	cout << "2. Exit" << endl;
	cout << "원하는 옵션을 입력해주세요. : ";
	cin >> menuOption;
	selectMenu(menuOption, fp);
}

void selectMenu(int menuOption, FILE* fp) {

	switch (menuOption) {
	case 0:
		if (x32Flag) {
			ViewHex_32(fp);
		}
		else {
			//ViewHex_64(fp);
		}
		ViewMenu(fp);
		break;
	case 1:
		if (x32Flag) {
			//ViewPE_32(fp);
		}
		else {
			//ViewPE_64(fp);
		}
		ViewMenu(fp);
		break;
	default:
		break;
	}
}

void ViewHex_32(FILE* fp) {
	char buff[BUFFER_SIZE] = { 0 };
	char decodedBuff[BUFFER_SIZE + 1] = { 0 };
	long offset = 0;
	int read = 0;
	int num = 0;

	fseek(fp, 0, SEEK_SET);

	cout << "Offset(h)\t00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F \tDecoded text" << endl;
	while ((read = fread(&buff, sizeof(char), BUFFER_SIZE, fp)) != 0) {
		printf("%.8X\t", offset);
		for (num = 0; num < read; num++) {
			printf("%.2X ", buff[num] & 0xFF);
			if ((buff[num] & 0xFF) >= 33 && (buff[num] & 0xFF) <= 126) {
				decodedBuff[num] = buff[num];
			}
			else {
				decodedBuff[num] = 46;
			}
		}
		offset += read;
		cout << "\t" << decodedBuff << endl;
		//printf("\t%s\n", decodedBuff);
	}
}