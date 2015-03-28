/*
*	MPQSigner - Signs MPQ files with a Blizzard Weak Digital Signature
*	Copyright (C) 2014-2015  xboi209 (xboi209@gmail.com)
*
*	This program is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*
*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License
*	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define MPQSIGNER_VERSION "1.1.0"

#if defined(_WIN32) && !defined(WIN32)
#define WIN32 
#endif

#include <iostream>
#include <string>
#include "StormLib.h"
#include <boost/filesystem.hpp>


int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cout << "Invalid number of arguments(need 2, got " << argc << ")" << std::endl;
		return -1;
	}

	std::cout << "MPQSigner v" << MPQSIGNER_VERSION << " - Sign MPQ files for a Blizzard Weak Digital Signature" << std::endl;
	std::cout << "by xboi209(xboi209@gmail.com) - 2014-2015" << std::endl;
	std::cout << std::endl;

	boost::filesystem::path p(argv[1]);

	if (p.string() == "--help")
	{
		std::cout << "Usage: MPQSigner <filename>" << std::endl;
		return 0;
	}

	if (p.string() == "--about")
	{
		std::cout << "MPQSigner v" << STORMLIB_VERSION_STRING << " by xboi209" << std::endl;
		std::cout << "StormLib v" << STORMLIB_VERSION_STRING << " by Ladislav Zezula" << std::endl;
		std::cout << "Blizzard Weak Digital Signature private key by Tesseract2048(Tianyi HE)" << std::endl;
		return 0;
	}

	if (!boost::filesystem::exists(p))
	{
		std::cout << p.string() << " does not exist" << std::endl;
		return -1;
	}

	if (!boost::filesystem::is_regular_file(p))
	{
		std::cout << p.string() << " is not a regular file" << std::endl;
		return -1;
	}

	SFILE_CREATE_MPQ mpqinfo;
	std::memset(&mpqinfo, 0, sizeof(SFILE_CREATE_MPQ));
	mpqinfo.cbSize = sizeof(SFILE_CREATE_MPQ);
	mpqinfo.dwMpqVersion = MPQ_FORMAT_VERSION_1; /* Version 1.0 */
	mpqinfo.dwStreamFlags = STREAM_PROVIDER_FLAT | BASE_PROVIDER_FILE;
	mpqinfo.dwFileFlags1 = 1; /* Use (listfile) */
	mpqinfo.dwFileFlags2 = 1; /* Use (attributes) file */
	mpqinfo.dwFileFlags3 = MPQ_FILE_EXISTS; /* Use (signature) file */
	mpqinfo.dwAttrFlags = MPQ_ATTRIBUTE_CRC32 | MPQ_ATTRIBUTE_FILETIME | MPQ_ATTRIBUTE_MD5;
	mpqinfo.dwSectorSize = 0x1000;
	mpqinfo.dwRawChunkSize = 0; /* Used only if MPQ v4 */
	mpqinfo.dwMaxFileCount = HASH_TABLE_SIZE_MIN;
	HANDLE hArchive;
	std::string mpqname = p.stem().string(); mpqname += ".mpq"; /* Filename with .mpq extension */

	if (p.has_extension())
	{
		if (p.extension() != ".mpq")
		{
			if (SFileCreateArchive2(mpqname.c_str(), &mpqinfo, &hArchive))
			{
				std::cout << "Created archive " << mpqname << std::endl;
			}
			else
			{
				std::cout << "Could not create archive " << mpqname << std::endl;
				return -1;
			}
		}
		else /* File has .mpq extension, just open and sign it */
		{
			SFileOpenArchive(p.string().c_str(), 0/* unused */, STREAM_PROVIDER_FLAT | BASE_PROVIDER_FILE, &hArchive);
			goto signArchive;
		}
	}
	else /* File with no extension */
	{
		if (SFileCreateArchive2(mpqname.c_str(), &mpqinfo, &hArchive))
		{
			std::cout << "Created archive " << mpqname << std::endl;
		}
		else
		{
			std::cout << "Could not create archive " << mpqname << std::endl;
			return -1;
		}
	}

	if (SFileAddFileEx(hArchive, p.string().c_str(), p.string().c_str(), MPQ_FILE_COMPRESS | MPQ_FILE_SECTOR_CRC, MPQ_COMPRESSION_PKWARE, MPQ_COMPRESSION_NEXT_SAME))
	{
		std::cout << "Added file " << p.string() << " to archive" << std::endl;

		/* informational, can be removed */
		HANDLE hFile;
		if (SFileOpenFileEx(hArchive, p.string().c_str(), SFILE_OPEN_FROM_MPQ, &hFile))
		{
			DWORD szFilehigh;
			DWORD szFilelow;
			szFilelow = SFileGetFileSize(hFile, &szFilehigh);
			if (szFilelow != SFILE_INVALID_SIZE)
			{
				std::cout << "File size(low): " << szFilelow << std::endl;
				std::cout << "File size(high): " << szFilehigh << std::endl;
			}
		}
	}
	else
	{
		std::cout << "Could not add file " << p.string() << " to archive" << std::endl;
		SFileCloseArchive(hArchive);
		return -1;
	}

	/*
	*	http://www.zezula.net/en/mpq/stormlib/sfileverifyfile.html
	*	Documentation is unclear to me...
	*/
	switch (SFileVerifyFile(hArchive, p.string().c_str(), SFILE_VERIFY_SECTOR_CRC))
	{
	case VERIFY_OPEN_ERROR:
		std::cout << "Could not open file " << p.string() << std::endl;
		break;
	case VERIFY_READ_ERROR:
		std::cout << "Could not read file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_HAS_SECTOR_CRC:
		std::cout << "Verified sector CRC of file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_SECTOR_CRC_ERROR:
		std::cout << "Verification of sector CRC of file " << p.string() << " failed" << std::endl;
		break;
	default:
		std::cout << "An error has occurred" << std::endl;
		break;
	}
	switch (SFileVerifyFile(hArchive, p.string().c_str(), SFILE_VERIFY_FILE_CRC))
	{
	case VERIFY_OPEN_ERROR:
		std::cout << "Could not open file " << p.string() << std::endl;
		break;
	case VERIFY_READ_ERROR:
		std::cout << "Could not read file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_HAS_CHECKSUM:
		std::cout << "Verified CRC32 of file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_CHECKSUM_ERROR:
		std::cout << "Verification of CRC32 of file " << p.string() << " failed" << std::endl;
		break;
	default:
		std::cout << "An error has occurred" << std::endl;
		break;
	}
	switch (SFileVerifyFile(hArchive, p.string().c_str(), SFILE_VERIFY_FILE_MD5))
	{
	case VERIFY_OPEN_ERROR:
		std::cout << "Could not open file " << p.string() << std::endl;
		break;
	case VERIFY_READ_ERROR:
		std::cout << "Could not read file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_HAS_MD5:
		std::cout << "Verified MD5 of file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_MD5_ERROR:
		std::cout << "Verification of MD5 of file " << p.string() << " failed" << std::endl;
		break;
	default:
		std::cout << "An error has occurred" << std::endl;
		break;
	}


signArchive:
	switch (SFileVerifyArchive(hArchive))
	{
	case ERROR_NO_SIGNATURE:
		if (SFileSignArchive(hArchive, SIGNATURE_TYPE_WEAK))
		{
			std::cout << "Signed archive" << std::endl;
			std::cout << "Signature: Blizzard Weak Digital Signature" << std::endl;
		}
		else
		{
			std::cout << "Could not sign archive" << std::endl;
			SFileCloseArchive(hArchive);
			return -1;
		}
		break;
	case ERROR_VERIFY_FAILED:
		std::cout << "An error has occured during signature verification" << std::endl;
		SFileCloseArchive(hArchive);
		return -1;
	case ERROR_WEAK_SIGNATURE_OK:
		std::cout << "Signature: Blizzard Weak Digital Signature" << std::endl;
		break;
	case ERROR_WEAK_SIGNATURE_ERROR:
		std::cout << "An invalid Blizzard Weak Digital Signature was found" << std::endl;
		SFileCloseArchive(hArchive);
		return -1;
	case ERROR_STRONG_SIGNATURE_OK:
		std::cout << "Signature: Blizzard Strong Digital Signature" << std::endl;
		break;
	case ERROR_STRONG_SIGNATURE_ERROR:
		std::cout << "An invalid Blizzard Strong Digital Signature was found" << std::endl;
		SFileCloseArchive(hArchive);
		return -1;
	default:
		std::cout << "An error has occurred" << std::endl;
		SFileCloseArchive(hArchive);
		return -1;
	}


	if (SFileCompactArchive(hArchive, NULL, false) != 0)
	{
		std::cout << "Compacted archive" << std::endl;
	}
	else
	{
		std::cout << "Could not compact archive" << std::endl;
	}

closeArchive:
	if (SFileCloseArchive(hArchive))
	{
		std::cout << "Closed archive" << std::endl;
	}
	else
	{
		std::cout << "Could not close archive" << std::endl;
		return -1;
	}

	return 0;
}