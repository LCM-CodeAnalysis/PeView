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
void ViewCharacteristics(unsigned short characteristics);
const char* ViewSubsystem(unsigned short subsystem);
void ViewDataDirectory(IMAGE_DATA_DIRECTORY* dataDirectorys, int size);
void ViewImageSectionHeader(char* buff);
void ViewImportDirectoryTable(char* buff, FILE* fp);
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
	// 각 Characteristics 마다 무슨 권한인지 출력
	ViewCharacteristics(ifh->Characteristics);

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
	cout << "Subsystem : " << setfill('0') << setw(4) << hex << ioh->Subsystem << "\t" << ViewSubsystem(ioh->Subsystem) << endl;
	cout << "DllCharacteristics : " << setfill('0') << setw(4) << hex << ioh->DllCharacteristics << endl;
	cout << "SizeOfStackReserve : " << setfill('0') << setw(8) << hex << ioh->SizeOfStackReserve << endl;
	cout << "SizeOfStackCommit : " << setfill('0') << setw(8) << hex << ioh->SizeOfStackCommit << endl;
	cout << "SizeOfHeapReserve : " << setfill('0') << setw(8) << hex << ioh->SizeOfHeapReserve << endl;
	cout << "SizeOfHeapCommit : " << setfill('0') << setw(8) << hex << ioh->SizeOfHeapCommit << endl;
	cout << "LoaderFlags : " << setfill('0') << setw(8) << hex << ioh->LoaderFlags << endl;
	cout << "NumberOfRvaAndSizes : " << setfill('0') << setw(8) << hex << ioh->NumberOfRvaAndSizes << endl;

	// _IMAGE_DATA_DIRECTORY
	ViewDataDirectory(ioh->DataDirectory, sizeof(ioh->DataDirectory) / sizeof(IMAGE_DATA_DIRECTORY));
	cout << endl;

	// IMAGE_SECTION_HEADER
	for (int i = 0; i < ifh->NumberOfSections; i++) {
		ViewImageSectionHeader(buff + idh->e_lfanew + 0x78 + (ioh->NumberOfRvaAndSizes * 8) + (0x28 * i));
	}

	ViewImportDirectoryTable(buff, fp);
}

void ViewCharacteristics(unsigned short characteristics) {
	if (characteristics & IMAGE_FILE_RELOCS_STRIPPED) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_RELOCS_STRIPPED << "\tIMAGE_FILE_RELOCS_STRIPPED" << endl;
	if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_EXECUTABLE_IMAGE << "\tIMAGE_FILE_EXECUTABLE_IMAGE" << endl;
	if (characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_LINE_NUMS_STRIPPED << "\tIMAGE_FILE_LINE_NUMS_STRIPPED" << endl;
	if (characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_LOCAL_SYMS_STRIPPED << "\tIMAGE_FILE_LOCAL_SYMS_STRIPPED" << endl;
	if (characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_AGGRESIVE_WS_TRIM << "\tIMAGE_FILE_AGGRESIVE_WS_TRIM" << endl;
	if (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_LARGE_ADDRESS_AWARE << "\tIMAGE_FILE_LARGE_ADDRESS_AWARE" << endl;
	if (characteristics & IMAGE_FILE_BYTES_REVERSED_LO) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_BYTES_REVERSED_LO << "\tIMAGE_FILE_BYTES_REVERSED_LO" << endl;
	if (characteristics & IMAGE_FILE_32BIT_MACHINE) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_32BIT_MACHINE << "\tIMAGE_FILE_32BIT_MACHINE" << endl;
	if (characteristics & IMAGE_FILE_DEBUG_STRIPPED) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_DEBUG_STRIPPED << "\tIMAGE_FILE_DEBUG_STRIPPED" << endl;
	if (characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP << "\tIMAGE_FILE_REMOVABLE_RUN_FROM_SWAP" << endl;
	if (characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_NET_RUN_FROM_SWAP << "\tIMAGE_FILE_NET_RUN_FROM_SWAP" << endl;
	if (characteristics & IMAGE_FILE_SYSTEM) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_SYSTEM << "\tIMAGE_FILE_SYSTEM" << endl;
	if (characteristics & IMAGE_FILE_DLL) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_DLL << "\tIMAGE_FILE_DLL" << endl;
	if (characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_UP_SYSTEM_ONLY << "\tIMAGE_FILE_UP_SYSTEM_ONLY" << endl;
	if (characteristics & IMAGE_FILE_BYTES_REVERSED_HI) cout << "\t" << setfill('0') << setw(4) << IMAGE_FILE_BYTES_REVERSED_HI << "\tIMAGE_FILE_BYTES_REVERSED_HI" << endl;
}

const char* ViewSubsystem(unsigned short subsystem) {
	if (subsystem & IMAGE_SUBSYSTEM_NATIVE) {
		return "IMAGE_SUBSYSTEM_NATIVE";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_WINDOWS_GUI) {
		return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_WINDOWS_CUI) {
		return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_OS2_CUI) {
		return "IMAGE_SUBSYSTEM_OS2_CUI";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_POSIX_CUI) {
		return "IMAGE_SUBSYSTEM_POSIX_CUI";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_NATIVE_WINDOWS) {
		return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) {
		return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_EFI_APPLICATION) {
		return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
		return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
		return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_EFI_ROM) {
		return "IMAGE_SUBSYSTEM_EFI_ROM";
	}
	else if (subsystem & IMAGE_SUBSYSTEM_XBOX) {
		return "IMAGE_SUBSYSTEM_XBOX";
	}
	else {
		return "IMAGE_SUBSYSTEM_UNKNOWN";
	}
}

void ViewDataDirectory(IMAGE_DATA_DIRECTORY* dataDirectorys, int size) {
	const char* directoryNameArr[16] = { "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_RESOURCE", "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
		"IMAGE_DIRECTORY_ENTRY_SECURITY", "IMAGE_DIRECTORY_ENTRY_BASERELOC", "IMAGE_DIRECTORY_ENTRY_DEBUG", "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE", "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
		"IMAGE_DIRECTORY_ENTRY_TLS", "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", "IMAGE_DIRECTORY_ENTRY_IAT", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", "" };
	for (int i = 0; i < size; i++) {
		cout << "\tRVA : " << setfill('0') << setw(8) << hex << dataDirectorys[i].VirtualAddress << "\t" << directoryNameArr[i] << endl;
		cout << "\tSize : " << setfill('0') << setw(8) << hex << dataDirectorys[i].Size << endl;
	}
	if (size > 2) {
		importTableRVA = dataDirectorys[1].VirtualAddress;
		importTableSize = dataDirectorys[1].Size / 20;
	}
}

void ViewImageSectionHeader(char* buff) {
	struct _IMAGE_SECTION_HEADER* ish = (_IMAGE_SECTION_HEADER*)buff;
	cout << endl << "---------- [IMAGE_SECTION_HEADER " << ish->Name << "] ----------" << endl;
	cout << "\tName : " << (ish->Name)+1;
	cout << endl;
	cout << "\tVirtual Size : " << setfill('0') << setw(8) << hex << ish->Misc.VirtualSize << endl;
	cout << "\tRVA : " << setfill('0') << setw(8) << hex << ish->VirtualAddress << endl;
	cout << "\tSize of Raw Data : " << setfill('0') << setw(8) << hex << ish->SizeOfRawData << endl;
	cout << "\tPointer to Raw Data : " << setfill('0') << setw(8) << hex << ish->PointerToRawData << endl;
	cout << "\tPointer to Relocations : " << setfill('0') << setw(8) << hex << ish->PointerToRelocations << endl;
	cout << "\tPointer to Line Numbers : " << setfill('0') << setw(8) << hex << ish->PointerToLinenumbers << endl;
	cout << "\tNumber of Relocations : " << setfill('0') << setw(4) << hex << ish->NumberOfRelocations << endl;
	cout << "\tNumber of Line Numbers : " << setfill('0') << setw(4) << hex << ish->NumberOfLinenumbers << endl;
	cout << "\tCharacteristics : " << setfill('0') << setw(8) << hex << ish->Characteristics << endl;
	if (ish->Characteristics & IMAGE_SCN_CNT_CODE) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_CNT_CODE << "\tIMAGE_SCN_CNT_CODE" << endl;
	if (ish->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_CNT_INITIALIZED_DATA << "\tIMAGE_SCN_CNT_INITIALIZED_DATA" << endl;
	if (ish->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_CNT_UNINITIALIZED_DATA << "\tIMAGE_SCN_CNT_UNINITIALIZED_DATA" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_FARDATA) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_FARDATA << "\tIMAGE_SCN_MEM_FARDATA" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_PURGEABLE) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_PURGEABLE << "\tIMAGE_SCN_MEM_PURGEABLE" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_16BIT) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_16BIT << "\tIMAGE_SCN_MEM_16BIT" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_LOCKED) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_LOCKED << "\tIMAGE_SCN_MEM_LOCKED" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_PRELOAD) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_PRELOAD << "\tIMAGE_SCN_MEM_PRELOAD" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_DISCARDABLE << "\tIMAGE_SCN_MEM_DISCARDABLE" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_NOT_CACHED << "\tIMAGE_SCN_MEM_NOT_CACHED" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_NOT_PAGED << "\tIMAGE_SCN_MEM_NOT_PAGED" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_SHARED) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_SHARED << "\tIMAGE_SCN_MEM_SHARED" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_EXECUTE) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_EXECUTE << "\tIMAGE_SCN_MEM_EXECUTE" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_READ) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_READ << "\tIMAGE_SCN_MEM_READ" << endl;
	if (ish->Characteristics & IMAGE_SCN_MEM_WRITE) cout << "\t\t" << setfill('0') << setw(8) << hex << IMAGE_SCN_MEM_WRITE << "\tIMAGE_SCN_MEM_WRITE" << endl;

	// Find the section ImportDirectoryTable belong to
	if (importTableRVA >= (unsigned int)(ish->VirtualAddress) && importTableRVA <= ((unsigned int)(ish->VirtualAddress) + (unsigned int)(ish->Misc.VirtualSize))) {
		sectionRVA = ish->VirtualAddress;
		sectionRAW = ish->PointerToRawData;
	}
}

void ViewImportDirectoryTable(char* buff, FILE* fp) {
	if (importTableRVA == 0) {
		return;
	}

	cout << endl << endl << "---------- [IMPORT Directory Table] ----------" << endl;
	struct _IMAGE_IMPORT_DESCRIPTOR* importDirectorys = (_IMAGE_IMPORT_DESCRIPTOR*)(buff + (sectionRAW + importTableRVA - sectionRVA));
	char temp[30] = { 0 };
	for (int i = 0; i < importTableSize; i++) {
		cout << "Import Name Table RVA : " << setfill('0') << setw(8) << hex << importDirectorys[i].OriginalFirstThunk << endl;
		cout << "Time Date Stamp : " << setfill('0') << setw(8) << hex << importDirectorys[i].TimeDateStamp << endl;
		cout << "Forwarder Chain : " << setfill('0') << setw(8) << hex << importDirectorys[i].ForwarderChain << endl;
		fseek(fp, importDirectorys[i].Name - 0x1000 + 0x400, SEEK_SET);
		fgets(temp, 30, fp);
		cout << "Name RVA : " << setfill('0') << setw(8) << hex << importDirectorys[i].Name;
		if (importDirectorys[i].Name == 0 && importDirectorys[i].FirstThunk == 0) {
			cout << endl;
		}
		else {
			fseek(fp, importDirectorys[i].Name - 0x1000 + 0x400, SEEK_SET);
			fgets(temp, 30, fp);
			cout << "\t" << temp << endl;
		}
		cout << "Import Address Table RVA : " << setfill('0') << setw(8) << hex << importDirectorys[i].FirstThunk << endl;
		cout << "--------------------------------------------------" << endl;
	}
}