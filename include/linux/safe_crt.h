//==============================================================================
// Copyright (c) 2016-2026 Advanced Micro Devices, Inc. All rights reserved.
/// @author AMD Developer Tools Team
/// @file
/// @brief Linux definition of Windows safe CRT functions.
//==============================================================================

#ifndef SDL_UTILS_LINUX_SAFE_CRT_H_
#define SDL_UTILS_LINUX_SAFE_CRT_H_

#if !defined(_WIN32)

#include <stdarg.h>
#include <stdio.h>

/// _TRUNCATE is a Microsoft-specific constant used with the _s family of functions
/// to indicate that the output should be truncated rather than treated as an error.
#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif

// In case any external headers define macros that map safe CRT function names
// to their unsafe equivalents (e.g., #define strcpy_s(dst, n, src) strcpy(dst, src)). These
// macros must be removed before we can declare the actual safe CRT functions below.
#ifdef fopen_s
#undef fopen_s
#endif
#ifdef sprintf_s
#undef sprintf_s
#endif
#ifdef fprintf_s
#undef fprintf_s
#endif
#ifdef memmove_s
#undef memmove_s
#endif
#ifdef memcpy_s
#undef memcpy_s
#endif
#ifdef strcpy_s
#undef strcpy_s
#endif
#ifdef strncpy_s
#undef strncpy_s
#endif
#ifdef strcat_s
#undef strcat_s
#endif
#ifdef fread_s
#undef fread_s
#endif
#ifdef sscanf_s
#undef sscanf_s
#endif
#ifdef vsnprintf_s
#undef vsnprintf_s
#endif

/// errno_t is not defined in C++11 but Microsoft use it in some of their function definitions
/// so define it here for Linux so the function prototypes match the Windows function prototypes.
typedef int errno_t;

/// @brief fopen_s secure version of fopen.
///
/// @param [out] file     A pointer to the file pointer that will receive the pointer to the opened file.
/// @param [in]  filename The filename of the file to be opened.
/// @param [in]  mode     Type of access permitted.
///
/// @return Zero if successful; an error code on failure.
errno_t fopen_s(FILE** file, const char* filename, const char* mode);

/// @brief sprintf_s secure version of sprintf.
///
/// @param [out] buffer         Storage location for output.
/// @param [in]  size_of_buffer Maximum number of characters to store.
/// @param [in]  format         Format-control string.
/// @param [in]  ...            Optional arguments to be formatted.
///
/// @return The number of characters written or -1 if an error occurred.
int sprintf_s(char* buffer, size_t size_of_buffer, const char* format, ...);

/// @brief fprintf_s secure version of fprintf.
///
/// @param [in,out] stream Pointer to FILE structure.
/// @param [in]     format Format-control string.
/// @param [in]     ...    Optional arguments to be formatted.
///
/// @return The number of bytes written, or a negative value when an output error occurs.
int fprintf_s(FILE* stream, const char* format, ...);

/// @brief memmove_s secure version of memmove.
///
/// Same validation as memcpy_s but uses memmove internally to handle overlapping regions.
///
/// @param [out] dest      Destination buffer.
/// @param [in]  dest_size Size of the destination buffer in bytes.
/// @param [in]  src       Source buffer to copy from.
/// @param [in]  count     Number of bytes to copy.
///
/// @return Zero if successful; an error code on failure.
errno_t memmove_s(void* dest, size_t dest_size, const void* src, size_t count);

/// @brief memcpy_s secure version of memcpy.
///
/// @param [out] dest      Destination buffer.
/// @param [in]  dest_size Size of the destination buffer in bytes.
/// @param [in]  src       Source buffer to copy from.
/// @param [in]  count     Number of bytes to copy.
///
/// @return Zero if successful; an error code on failure.
errno_t memcpy_s(void* dest, size_t dest_size, const void* src, size_t count);

/// @brief strcpy_s secure version of strcpy.
///
/// @param [out] dest      Destination string buffer.
/// @param [in]  dest_size Size of the destination string buffer in characters.
/// @param [in]  src       Null-terminated source string buffer.
///
/// @return Zero if successful; an error code on failure.
errno_t strcpy_s(char* dest, size_t dest_size, const char* src);

/// @brief strncpy_s secure version of strncpy.
///
/// Copies at most @p count characters from @p src to @p dest and always
/// null-terminates the result within @p dest_size. If @p count is _TRUNCATE,
/// the source is silently truncated to fit (dest_size - 1) characters.
/// Otherwise, if @p count would not leave room for the null terminator within
/// @p dest_size (i.e. count >= dest_size), the call fails with ERANGE.
///
/// Unlike the unsafe strncpy, this function does NOT null-pad @p dest beyond
/// the terminating null character when @p src is shorter than @p count.
/// This matches Windows CRT strncpy_s and C11 Annex K semantics.
///
/// @param [out] dest      Destination string buffer.
/// @param [in]  dest_size Size of the destination string buffer in characters.
/// @param [in]  src       Null-terminated source string buffer.
/// @param [in]  count     Maximum number of characters to copy from @p src,
///                        or _TRUNCATE to copy as much as fits.
///
/// @return Zero if successful; an error code on failure.
errno_t strncpy_s(char* dest, size_t dest_size, const char* src, size_t count);

/// @brief strcat_s secure version of strcat.
///
/// Appends @p src to the null-terminated string in @p dest. The combined
/// length (existing dest content + src + null terminator) must fit within
/// @p dest_size, otherwise the call fails with ERANGE and @p dest is reset
/// to an empty string. If @p dest is not null-terminated within @p dest_size,
/// the call fails with EINVAL.
///
/// @param [in,out] dest      Destination string buffer (must be null-terminated within dest_size on entry).
/// @param [in]     dest_size Size of the destination string buffer in characters.
/// @param [in]     src       Null-terminated source string buffer to append.
///
/// @return Zero if successful; an error code on failure.
errno_t strcat_s(char* dest, size_t dest_size, const char* src);

/// @brief fread_s secure version of fread.
///
/// @param [out] buffer       Storage location for data.
/// @param [in]  buffer_size  Size of the destination buffer in bytes.
/// @param [in]  element_size Size of the item to read in bytes.
/// @param [in]  count        Maximum number of items to be read.
/// @param [in]  stream       Pointer to FILE structure.
///
/// @return The number of (whole) items that were read into the buffer, which may be less than count if a
///         read error or the end of the file is encountered before count is reached. Use the feof or ferror
///         function to distinguish an error from an end-of-file condition. If size or count is 0, fread_s
///         returns 0 and the buffer contents are unchanged.
size_t fread_s(void* buffer, size_t buffer_size, size_t element_size, size_t count, FILE* stream);

/// @brief sscanf_s secure version of sscanf.
///
/// Thin wrapper around vsscanf with format specifier validation. This implementation does NOT
/// support %s and %[ specifiers (which require buffer-size arguments on Windows). Using these
/// specifiers will return EOF and set errno to EINVAL. Single-character %c and numeric specifiers
/// (%d, %f, etc.) are supported and safe.
///
/// @param [in] buffer Input string to parse.
/// @param [in] format Format-control string.
/// @param [in] ...    Optional arguments to receive formatted input.
///
/// @return The number of fields successfully converted and assigned, or EOF on error.
int sscanf_s(const char* buffer, const char* format, ...);

/// @brief vsnprintf_s secure version of vsnprintf.
///
/// Writes formatted output to a buffer with bounds checking. When count is _TRUNCATE,
/// the output is silently truncated to fit the buffer and the function returns -1.
///
/// @param [out] buffer         Storage location for output.
/// @param [in]  size_of_buffer Size of the buffer in characters.
/// @param [in]  count          Maximum number of characters to write (not including the null terminator),
///                             or _TRUNCATE to write as much as fits.
/// @param [in]  format         Format-control string.
/// @param [in]  arg_ptr        Pointer to list of arguments.
///
/// @return The number of characters written (not including the null terminator), or -1 if truncation
///         occurred or an error was detected.
int vsnprintf_s(char* buffer, size_t size_of_buffer, size_t count, const char* format, va_list arg_ptr);

#endif  // !_WIN32

#endif  // SDL_UTILS_LINUX_SAFE_CRT_H_
