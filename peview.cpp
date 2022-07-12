#include <iostream>
#include <iomanip>
#include <cstdio>
#include <stdlib.h>
#include <Windows.h>

#define BUFFER_SIZE 16

using namespace std;

bool CheckSignature(FILE* fp);
void CheckX32(FILE* fp);
void ViewMenu(FILE* fp);
void selectMenu(int menuOption, FILE* fp);
void ViewHex_32(FILE* fp);
void ViewPE_32(FILE* fp);
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
		CheckX32(fp);
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

void CheckX32(FILE* fp) {
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
			ViewPE_32(fp);
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
		cout << setfill('0') << setw(8) << hex << offset << "\t";
		for (num = 0; num < read; num++) {
			cout << setfill('0') << setw(2) << hex << (buff[num] & 0xFF) << ' ';
			if ((buff[num] & 0xFF) >= 33 && (buff[num] & 0xFF) <= 126) {
				decodedBuff[num] = buff[num];
			}
			else {
				decodedBuff[num] = 46;
			}
		}
		offset += read;
		cout << "\t" << decodedBuff << endl;
	}
}

void ViewPE_32(FILE* fp) {

	int fileSize, count;
	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);

	char* buff = new char[fileSize+1];
	fseek(fp, 0, SEEK_SET);
	count = fread(buff, fileSize, 1, fp);

	// IMAGE_DOS_HEADER
	struct _IMAGE_DOS_HEADER* idh = (_IMAGE_DOS_HEADER *)buff;
	cout << endl << "---------- [IMAGE_DOS_HEADER] ----------" << endl;
	cout << "e_magic : " << setfill('0') << setw(4) << hex << idh->e_magic << endl;
	cout << "e_lfanew : " << setfill('0') << setw(8) << hex << idh->e_lfanew << endl;

	// IMAGE_NT_HEADERS
	struct _IMAGE_NT_HEADERS* inh = (_IMAGE_NT_HEADERS *)(buff + idh->e_lfanew);
	cout << endl << "---------- [IMAGE_NT_HEADERS > Signature] ----------" << endl;
	cout << "Signature : " << setfill('0') << setw(8) << hex << inh->Signature << endl;

	struct _IMAGE_FILE_HEADER *ifh = &(inh->FileHeader);
	cout << "---------- [IMAGE_NT_HEADERS > IMAGE_FILE_HEADER] ----------" << endl;
	cout << "Machine : " << setfill('0') << setw(4) << hex << ifh->Machine << endl;
	cout << "Number of Sections : " << setfill('0') << setw(4) << hex << ifh->NumberOfSections << endl;
	cout << "Time Date Stamp : " << setfill('0') << setw(8) << hex << ifh->TimeDateStamp << endl;
	cout << "Size of Optional Header : " << setfill('0') << setw(4) << hex << ifh->SizeOfOptionalHeader << endl;
	cout << "Characteristics : " << setfill('0') << setw(4) << hex << ifh->Characteristics << endl;

	struct _IMAGE_OPTIONAL_HEADER* ioh = &(inh->OptionalHeader);
	cout << "---------- [IMAGE_NT_HEADERS > IMAGE_OPTIONAL_HEADER32] ----------" << endl;
	cout << "Magic : " << setfill('0') << setw(4) << hex << ioh->Magic << endl;
	cout << "MajorLinkerVersion : " << setfill('0') << setw(2) << hex << (unsigned short)(ioh->MajorLinkerVersion) << endl;
	cout << "MinorLinkerVersion : " << setfill('0') << setw(2) << hex << (unsigned short)(ioh->MinorLinkerVersion) << endl;
	cout << "SizeOfCode : " << setfill('0') << setw(8) << hex << ioh->SizeOfCode << endl;
	cout << "SizeOfInitializedData : " << setfill('0') << setw(8) << hex << ioh->SizeOfInitializedData << endl;
	cout << "SizeOfUninitializedData : " << setfill('0') << setw(8) << hex << ioh->SizeOfUninitializedData << endl;
	cout << "AddressOfEntryPoint : " << setfill('0') << setw(8) << hex << ioh->AddressOfEntryPoint << endl;
	cout << "BaseOfCode : " << setfill('0') << setw(8) << hex << ioh->BaseOfCode << endl;
	cout << "BaseOfData : " << setfill('0') << setw(8) << hex << ioh->BaseOfData << endl;
	cout << "ImageBase : " << setfill('0') << setw(8) << hex << ioh->ImageBase << endl;
	cout << "SectionAlignment : " << setfill('0') << setw(8) << hex << ioh->SectionAlignment << endl;
	cout << "FileAlignment : " << setfill('0') << setw(8) << hex << ioh->FileAlignment << endl;
	cout << "MajorOperatingSystemVersion : " << setfill('0') << setw(4) << hex << ioh->MajorOperatingSystemVersion << endl;
	cout << "MinorOperatingSystemVersion : " << setfill('0') << setw(4) << hex << ioh->MinorOperatingSystemVersion << endl;
	cout << "MajorImageVersion : " << setfill('0') << setw(4) << hex << ioh->MajorImageVersion << endl;
	cout << "MinorImageVersion : " << setfill('0') << setw(4) << hex << ioh->MinorImageVersion << endl;
	cout << "MajorSubsystemVersion : " << setfill('0') << setw(4) << hex << ioh->MajorSubsystemVersion << endl;
	cout << "MinorSubsystemVersion : " << setfill('0') << setw(4) << hex << ioh->MinorSubsystemVersion << endl;
	cout << "Win32VersionValue : " << setfill('0') << setw(8) << hex << ioh->Win32VersionValue << endl;
	cout << "SizeOfImage : " << setfill('0') << setw(8) << hex << ioh->SizeOfImage << endl;
	cout << "SizeOfHeaders : " << setfill('0') << setw(8) << hex << ioh->SizeOfHeaders << endl;
	cout << "CheckSum : " << setfill('0') << setw(8) << hex << ioh->CheckSum << endl;
	cout << "Subsystem : " << setfill('0') << setw(4) << hex << ioh->Subsystem << endl;
	cout << "DllCharacteristics : " << setfill('0') << setw(4) << hex << ioh->DllCharacteristics << endl;
	cout << "SizeOfStackReserve : " << setfill('0') << setw(8) << hex << ioh->SizeOfStackReserve << endl;
	cout << "SizeOfStackCommit : " << setfill('0') << setw(8) << hex << ioh->SizeOfStackCommit << endl;
	cout << "SizeOfHeapReserve : " << setfill('0') << setw(8) << hex << ioh->SizeOfHeapReserve << endl;
	cout << "SizeOfHeapCommit : " << setfill('0') << setw(8) << hex << ioh->SizeOfHeapCommit << endl;
	cout << "LoaderFlags : " << setfill('0') << setw(8) << hex << ioh->LoaderFlags << endl;
	cout << "NumberOfRvaAndSizes : " << setfill('0') << setw(8) << hex << ioh->NumberOfRvaAndSizes << endl;
}