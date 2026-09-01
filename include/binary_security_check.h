//=============================================================================
// Copyright (c) 2026 Advanced Micro Devices, Inc. All rights reserved.
/// @author AMD Developer Tools Team
/// @file
/// @brief Header file to check valid signatures of binaries (DLLs and EXEs) at runtime to detect proxy attacks.
//=============================================================================

// This header provides runtime security validation to detect proxy attacks
// and suspicious binary replacements. It should be called early in application
// startup to validate binary integrity. These checks are only performed on Windows platforms
// and only if the main application binary is signed. If the main binary is unsigned, the
// checks are skipped to avoid false positives in development builds.
//
// Detection Methods:
// - Invalid digital signatures on any binaries in the application's directory (or its subdirectories)
// - Tampered or modified binaries

#ifndef SDL_UTILS_BINARY_SECURITY_CHECK_H_
#define SDL_UTILS_BINARY_SECURITY_CHECK_H_

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

// Windows SDK headers must be included in dependency order (windows.h first),
// not alphabetically, as wintrust.h and softpub.h depend on base types from windows.h
#include <windows.h>

#include <softpub.h>
#include <tchar.h>
#include <wintrust.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <future>
#include <iterator>
#include <limits>
#include <string>
#include <thread>
#include <vector>

namespace BinarySecurity
{
    /// @brief FloatingString will float between std::string and std::wstring based on UNICODE definition.
#if defined(UNICODE) || defined(_UNICODE)
    using FloatingString       = std::wstring;
    constexpr auto CharToLower = static_cast<wint_t (*)(wint_t)>(::towlower);
#else
    using FloatingString = std::string;

    /// @brief Safely convert a character to lowercase, casting through unsigned char to avoid
    ///        undefined behavior when char is signed and the value is negative (non-ASCII bytes).
    static inline char CharToLower(char c)
    {
        return static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    }
#endif

    /// @brief Helper function to get the module file name with a dynamic buffer to support long paths.
    ///
    /// @param out_path Output parameter to receive the module file name.
    ///
    /// @return true if the module file name was successfully retrieved, false otherwise.
    inline bool GetModuleFileNameWithDynamicBuffer(FloatingString& out_path)
    {
        out_path.resize(MAX_PATH, _T('\0'));
        DWORD path_len = GetModuleFileName(NULL, &out_path[0], static_cast<DWORD>(out_path.size()));
        while (path_len != 0 && path_len >= static_cast<DWORD>(out_path.size()))
        {
            out_path.resize(out_path.size() * 2, _T('\0'));
            path_len = GetModuleFileName(NULL, &out_path[0], static_cast<DWORD>(out_path.size()));
        }

        if (path_len == 0)
        {
            return false;
        }

        out_path.resize(path_len);
        return true;
    }

    /// @brief Helper function to convert size_t to FloatingString.
    ///
    /// @param value The size_t value to convert.
    ///
    /// @return The converted FloatingString.
    inline FloatingString ToFloatingString(size_t value)
    {
#if defined(UNICODE) || defined(_UNICODE)
        return std::to_wstring(value);
#else
        return std::to_string(value);
#endif
    }

    /// @brief Helper function to check if a string ends with a given suffix (C++17 compatible).
    ///
    /// @param str    The string to check.
    /// @param suffix The suffix to look for.
    ///
    /// @return true if str ends with suffix.
    inline bool EndsWith(const FloatingString& str, const FloatingString& suffix)
    {
        if (str.length() < suffix.length())
        {
            return false;
        }
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    }

    /// @brief Results from binary security scan.
    struct SecurityScanResult
    {
        bool                        is_secure;         ///< Overall security status.
        std::vector<FloatingString> suspicious_files;  ///< List of suspicious binaries found.
        std::vector<FloatingString> warnings;          ///< Non-critical warnings.
        FloatingString              root_path;         ///< Root directory of the scan, used for relative path display.
    };

    /// @brief A file collected during directory scanning that needs signature verification.
    struct PendingVerification
    {
        FloatingString full_path;     ///< Absolute path for WinVerifyTrust.
        FloatingString display_path;  ///< Relative path for error reporting.
    };

    /// @brief Call WinVerifyTrust on a file and return the raw result code.
    ///
    /// @param file_path Full path to the file to verify.
    ///
    /// @return The LONG result from WinVerifyTrust (0 = valid signature,
    ///         TRUST_E_NOSIGNATURE = unsigned, other = invalid/tampered).
    inline LONG VerifyFileSignature(const FloatingString& file_path)
    {
        if (file_path.empty())
        {
            return E_UNEXPECTED;
        }

        WINTRUST_FILE_INFO file_info = {};
        file_info.cbStruct           = sizeof(WINTRUST_FILE_INFO);
#if defined(UNICODE) || defined(_UNICODE)
        file_info.pcwszFilePath = file_path.c_str();
#else
        // Convert ANSI (ACP) char* path to UTF-16 std::wstring using Win32 API.
        std::wstring wfile_path;

        // MultiByteToWideChar expects int lengths; guard against extremely large inputs.
        if (file_path.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        {
            return E_UNEXPECTED;
        }

        int src_len = static_cast<int>(file_path.size());

        // First call to determine required buffer size (excluding null terminator).
        int required_len = ::MultiByteToWideChar(CP_ACP, 0, file_path.c_str(), src_len, nullptr, 0);
        if (required_len <= 0)
        {
            return E_UNEXPECTED;
        }

        wfile_path.resize(static_cast<size_t>(required_len));

        // Second call to perform the actual conversion.
        int converted_len = ::MultiByteToWideChar(CP_ACP, 0, file_path.c_str(), src_len, &wfile_path[0], required_len);
        if (converted_len <= 0)
        {
            return E_UNEXPECTED;
        }

        // Remove the null terminator from the std::wstring length if present.
        if (!wfile_path.empty() && wfile_path.back() == L'\0')
        {
            wfile_path.pop_back();
        }

        file_info.pcwszFilePath = wfile_path.c_str();
#endif
        file_info.hFile          = NULL;
        file_info.pgKnownSubject = NULL;

        GUID guid_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trust_data       = {};
        trust_data.cbStruct            = sizeof(WINTRUST_DATA);
        trust_data.dwUIChoice          = WTD_UI_NONE;
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust_data.dwUnionChoice       = WTD_CHOICE_FILE;
        trust_data.pFile               = &file_info;
        trust_data.dwStateAction       = WTD_STATEACTION_VERIFY;
        trust_data.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

        LONG result = WinVerifyTrust(NULL, &guid_action, &trust_data);

        // Cleanup.
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &guid_action, &trust_data);

        return result;
    }

    /// @brief Check if a file has a valid digital signature.
    ///
    /// @param file_path Full path to the file to check.
    ///
    /// @return true if signature is valid, false if signature is missing or invalid.
    inline bool HasValidSignature(const FloatingString& file_path)
    {
        return VerifyFileSignature(file_path) == 0;
    }

    /// @brief Remediation message appended to security warning dialogs.
    constexpr auto kRemediationMessage = _T("\nPlease reinstall the application.");

    /// @brief Maximum recursion depth for directory scanning.
    constexpr size_t kMaxScanDepth = 16;

    /// @brief Recursively scan directory and collect binaries that need signature verification.
    ///
    /// Handles directory enumeration, reparse point detection, and depth limiting.
    /// Does not perform signature verification -- callers must verify the collected files separately.
    ///
    /// @param directory_path  Directory to scan.
    /// @param result          Output results structure (for directory-level warnings only).
    /// @param files_to_verify Output list of files needing signature verification.
    /// @param skip_lower_name Lowercased filename to skip during signature checks (already verified by caller).
    /// @param depth           Current recursion depth (starts at 0, capped at kMaxScanDepth).
    inline void ScanDirectory(const FloatingString&             directory_path,
                              SecurityScanResult&               result,
                              std::vector<PendingVerification>& files_to_verify,
                              const FloatingString&             skip_lower_name = FloatingString(),
                              size_t                            depth           = 0)
    {
        if (depth >= kMaxScanDepth)
        {
            // Treat hitting maximum scan depth as a security failure, since the scan is incomplete.
            result.is_secure = false;
            result.warnings.push_back(_T("Maximum scan depth reached for: ") + directory_path);
            return;
        }

        FloatingString search_path = directory_path + _T("\\*");

        WIN32_FIND_DATA find_data;
        HANDLE          find_handle = FindFirstFile(search_path.c_str(), &find_data);
        if (find_handle == INVALID_HANDLE_VALUE)
        {
            // Treat enumeration failure as a security issue since we cannot
            // verify the contents of this directory.
            result.is_secure = false;
            result.warnings.push_back(_T("Directory enumeration failed for: ") + directory_path);
            return;
        }

        do
        {
            // Skip current and parent directory.
            if (_tcscmp(find_data.cFileName, _T(".")) == 0 || _tcscmp(find_data.cFileName, _T("..")) == 0)
            {
                continue;
            }

            // Build full path of current file.
            FloatingString full_path = directory_path + _T("\\") + find_data.cFileName;

            // Handle subdirectories. Do not follow reparse points (junctions/symlinks), but treat them as suspicious.
            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                {
                    FloatingString display_path = full_path;
                    if (!result.root_path.empty() && full_path.length() > result.root_path.length() + 1)
                    {
                        display_path = full_path.substr(result.root_path.length() + 1);
                    }
                    result.suspicious_files.push_back(_T("Reparse-point directory: ") + display_path);
                    continue;
                }

                ScanDirectory(full_path, result, files_to_verify, skip_lower_name, depth + 1);
                continue;
            }

            FloatingString file_name(find_data.cFileName);
            FloatingString lower_name = file_name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), CharToLower);

            // Collect binaries for later parallel verification (skip only the main executable already verified by caller at depth 0).
            if ((EndsWith(lower_name, _T(".dll")) || EndsWith(lower_name, _T(".exe"))) && !(depth == 0 && lower_name == skip_lower_name))
            {
                FloatingString display_path = full_path;
                if (!result.root_path.empty() && full_path.length() > result.root_path.length() + 1)
                {
                    display_path = full_path.substr(result.root_path.length() + 1);
                }
                files_to_verify.push_back({full_path, display_path});
            }

        } while (FindNextFile(find_handle, &find_data));

        DWORD last_error = GetLastError();

        if (last_error != ERROR_NO_MORE_FILES)
        {
            // Enumeration failed unexpectedly - treat as security issue.
            result.is_secure = false;
            result.warnings.push_back(_T("Directory enumeration error in: ") + directory_path + _T(" (Error code: ") + ToFloatingString(last_error) + _T(")"));
        }

        FindClose(find_handle);
    }

    /// @brief Verify files sequentially (fallback when parallel verification fails).
    /// @param files_to_verify Files collected by ScanDirectory.
    /// @param result          Output results structure to receive suspicious file entries.
    inline void VerifyFilesSequentially(const std::vector<PendingVerification>& files_to_verify, SecurityScanResult& result)
    {
        for (const auto& file : files_to_verify)
        {
            if (!HasValidSignature(file.full_path))
            {
                result.suspicious_files.push_back(_T("Invalid signature: ") + file.display_path);
            }
        }
    }

    /// @brief Verify files in parallel with exception handling and sequential fallback.
    /// @param files_to_verify Files collected by ScanDirectory.
    /// @param result          Output results structure to receive suspicious file entries.
    inline void VerifyFilesInParallel(const std::vector<PendingVerification>& files_to_verify, SecurityScanResult& result)
    {
        const size_t total_files = files_to_verify.size();
        if (total_files == 0)
        {
            return;
        }

        const size_t initial_size = result.suspicious_files.size();

        try
        {
            unsigned int thread_count = std::thread::hardware_concurrency();
            if (thread_count == 0)
            {
                thread_count = 4;
            }
            thread_count = std::min(thread_count, 16u);

            if (static_cast<size_t>(thread_count) > total_files)
            {
                thread_count = static_cast<unsigned int>(total_files);
            }
            const size_t chunk_size = total_files / thread_count;
            const size_t remainder  = total_files % thread_count;

            std::vector<std::future<std::vector<FloatingString>>> futures;
            futures.reserve(thread_count);

            size_t start = 0;
            for (unsigned int i = 0; i < thread_count; ++i)
            {
                size_t end = start + chunk_size + (i < remainder ? 1 : 0);

                futures.push_back(std::async(std::launch::async, [&files_to_verify, start, end]() -> std::vector<FloatingString> {
                    std::vector<FloatingString> local_suspicious;
                    for (size_t j = start; j < end; ++j)
                    {
                        if (!HasValidSignature(files_to_verify[j].full_path))
                        {
                            local_suspicious.push_back(_T("Invalid signature: ") + files_to_verify[j].display_path);
                        }
                    }
                    return local_suspicious;
                }));

                start = end;
            }

            for (auto& future : futures)
            {
                std::vector<FloatingString> local_result = future.get();
                result.suspicious_files.insert(
                    result.suspicious_files.end(), std::make_move_iterator(local_result.begin()), std::make_move_iterator(local_result.end()));
            }
        }
        catch (...)
        {
            // If parallel verification fails (e.g., std::system_error from std::async,
            // std::bad_alloc, or any exception from future.get()), fall back to sequential
            // verification to ensure security validation still completes.
            // Clear any partially-inserted results to prevent duplicates.
            result.suspicious_files.erase(result.suspicious_files.begin() + initial_size, result.suspicious_files.end());
            VerifyFilesSequentially(files_to_verify, result);
        }
    }

    /// @brief Perform comprehensive binary security scan.
    ///
    /// @param directory_path  Directory to scan.
    /// @param skip_lower_name Lowercased filename to skip during signature checks (already verified by caller).
    ///
    /// @return SecurityScanResult with findings.
    inline SecurityScanResult CheckBinarySecurity(const FloatingString& directory_path, const FloatingString& skip_lower_name = FloatingString())
    {
        SecurityScanResult result = {};
        result.is_secure          = true;
        result.root_path          = directory_path;

        // Phase 1: Collect files that need verification.
        std::vector<PendingVerification> files_to_verify;
        ScanDirectory(directory_path, result, files_to_verify, skip_lower_name);

        // Phase 2: Verify signatures in parallel.
        VerifyFilesInParallel(files_to_verify, result);

        // Determine overall security status.
        if (!result.suspicious_files.empty())
        {
            result.is_secure = false;
        }

        return result;
    }

    /// @brief Simple boolean check for binary security (for early startup validation).
    ///
    /// @param directory_path  Directory to scan.
    /// @param skip_lower_name Lowercased filename to skip during signature checks (already verified by caller).
    ///
    /// @return true if no security issues detected.
    inline bool ValidateBinarySecurity(const FloatingString& directory_path, const FloatingString& skip_lower_name = FloatingString())
    {
        SecurityScanResult result = CheckBinarySecurity(directory_path, skip_lower_name);

        if (!result.is_secure)
        {
            // Show error dialog on security failure.
            FloatingString message = _T("Binary Security Check Failed!\n");

            if (result.suspicious_files.size() > 0)
            {
                static const size_t kMaxDisplayFiles = 10;
                message += _T("\nSuspicious files detected:\n");
                for (size_t i = 0; i < result.suspicious_files.size() && i < kMaxDisplayFiles; i++)
                {
                    message += _T("- ") + result.suspicious_files[i] + _T("\n");
                }

                if (result.suspicious_files.size() > kMaxDisplayFiles)
                {
                    message += _T("... and ") + ToFloatingString(result.suspicious_files.size() - kMaxDisplayFiles) + _T(" more\n");
                }
            }

            if (result.warnings.size() > 0)
            {
                message += _T("\nWarnings:\n");
                for (size_t i = 0; i < result.warnings.size(); i++)
                {
                    message += _T("- ") + result.warnings[i] + _T("\n");
                }
            }

            message += _T("\nThis may indicate a security compromise.");
            message += kRemediationMessage;

            MessageBox(NULL, message.c_str(), _T("Security Warning"), MB_OK | MB_ICONWARNING | MB_TOPMOST);
        }

        return result.is_secure;
    }

    /// @brief Main entry point for installation validation. Checks binary integrity and detects proxy attacks.
    ///
    /// @return true if installation is valid and secure, false if a security issue is detected.
    inline bool IsInstallationValid()
    {
        // Validate binary integrity.
        // Detects proxy attacks and suspicious file modifications.

        // Get application directory. Check binary signatures if main application is signed.
        FloatingString exe_path;
        if (!GetModuleFileNameWithDynamicBuffer(exe_path))
        {
            FloatingString message = _T("Failed to get application path for security validation.");
            message += kRemediationMessage;
            MessageBox(NULL, message.c_str(), _T("Security Warning"), MB_OK | MB_ICONERROR | MB_TOPMOST);
            return false;
        }
        LONG verify_result = VerifyFileSignature(exe_path);
        if (verify_result == TRUST_E_NOSIGNATURE)
        {
            // Unsigned binary - development build, skip security scan.
        }
        else if (verify_result == 0)
        {
            // Extract the executable name and remove it to get the directory.
            FloatingString exe_lower_name;
            size_t         last_backslash = exe_path.rfind(_T('\\'));
            if (last_backslash != FloatingString::npos)
            {
                exe_lower_name = exe_path.substr(last_backslash + 1);
                std::transform(exe_lower_name.begin(), exe_lower_name.end(), exe_lower_name.begin(), CharToLower);
                exe_path.resize(last_backslash);
            }
            // Valid signature - run full security scan, skipping the exe we already verified.
            if (!ValidateBinarySecurity(exe_path, exe_lower_name))
            {
                // Security validation failed - exit application.
                return false;
            }
        }
        else
        {
            // Signature present but invalid or tampered - fail immediately.
            FloatingString message = _T("The application binary has an invalid or tampered digital signature.");
            message += kRemediationMessage;
            MessageBox(NULL, message.c_str(), _T("Security Warning"), MB_OK | MB_ICONERROR | MB_TOPMOST);
            return false;
        }
        return true;
    }

}  // namespace BinarySecurity

#endif  // _WIN32
#endif  // SDL_UTILS_BINARY_SECURITY_CHECK_H_
