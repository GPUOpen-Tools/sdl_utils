//==============================================================================
// Copyright (c) 2016-2026 Advanced Micro Devices, Inc. All rights reserved.
/// @author AMD Developer Tools Team
/// @file
/// @brief Linux implementation of Windows safe CRT functions.
//==============================================================================

#if !defined(_WIN32)

#include "linux/safe_crt.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

errno_t memmove_s(void* dest, size_t dest_size, const void* src, size_t count)
{
    if (count == 0)
    {
        return 0;
    }

    if (dest == nullptr)
    {
        return EINVAL;
    }

    if (src == nullptr)
    {
        memset(dest, 0, dest_size);
        return EINVAL;
    }

    if (count > dest_size)
    {
        memset(dest, 0, dest_size);
        return ERANGE;
    }

    memmove(dest, src, count);
    return 0;
}

errno_t memcpy_s(void* dest, size_t dest_size, const void* src, size_t count)
{
    if (count == 0)
    {
        return 0;
    }

    if (dest == nullptr)
    {
        return EINVAL;
    }

    if (src == nullptr)
    {
        memset(dest, 0, dest_size);
        return EINVAL;
    }

    if (count > dest_size)
    {
        memset(dest, 0, dest_size);
        return ERANGE;
    }

    // Check for overlapping memory regions (undefined behavior with memcpy).
    // Windows memcpy_s detects overlap and fails with EINVAL.
    const char* dest_begin = static_cast<const char*>(dest);
    const char* dest_end   = dest_begin + count;  // Use count, not dest_size
    const char* src_begin  = static_cast<const char*>(src);
    const char* src_end    = src_begin + count;

    if ((src_begin < dest_end && src_end > dest_begin))
    {
        memset(dest, 0, dest_size);
        return EINVAL;
    }

    memcpy(dest, src, count);
    return 0;
}

errno_t strcpy_s(char* dest, size_t dest_size, const char* src)
{
    if (dest == nullptr)
    {
        return EINVAL;
    }

    if (dest_size == 0)
    {
        return ERANGE;
    }

    if (src == nullptr)
    {
        dest[0] = '\0';
        return EINVAL;
    }

    size_t src_len = strlen(src);
    if (src_len >= dest_size)
    {
        dest[0] = '\0';
        return ERANGE;
    }

    memcpy(dest, src, src_len + 1);
    return 0;
}

errno_t strncpy_s(char* dest, size_t dest_size, const char* src, size_t count)
{
    if (dest == nullptr)
    {
        return EINVAL;
    }

    if (dest_size == 0)
    {
        return ERANGE;
    }

    if (src == nullptr)
    {
        dest[0] = '\0';
        return EINVAL;
    }

    // Determine how many characters from src may be copied. _TRUNCATE asks for
    // a silent truncation to fit; otherwise count must leave room for the
    // null terminator within dest_size.
    size_t copy_limit;
    if (count == _TRUNCATE)
    {
        copy_limit = dest_size - 1;
    }
    else if (count >= dest_size)
    {
        dest[0] = '\0';
        return ERANGE;
    }
    else
    {
        copy_limit = count;
    }

    size_t i = 0;
    while (i < copy_limit && src[i] != '\0')
    {
        dest[i] = src[i];
        ++i;
    }
    dest[i] = '\0';

    return 0;
}

errno_t strcat_s(char* dest, size_t dest_size, const char* src)
{
    if (dest == nullptr)
    {
        return EINVAL;
    }

    if (dest_size == 0)
    {
        return ERANGE;
    }

    if (src == nullptr)
    {
        dest[0] = '\0';
        return EINVAL;
    }

    // Find the existing length of dest within dest_size. If there is no null
    // terminator inside the buffer, treat dest as malformed.
    size_t dest_len = 0;
    while (dest_len < dest_size && dest[dest_len] != '\0')
    {
        ++dest_len;
    }
    if (dest_len == dest_size)
    {
        dest[0] = '\0';
        return EINVAL;
    }

    size_t src_len  = strlen(src);
    size_t remaining = dest_size - dest_len;  // Safe: dest_len < dest_size is guaranteed above.
    if (src_len >= remaining)
    {
        dest[0] = '\0';
        return ERANGE;
    }

    memcpy(dest + dest_len, src, src_len + 1);
    return 0;
}

errno_t fopen_s(FILE** file, const char* filename, const char* mode)
{
    if (file == nullptr)
    {
        errno = EINVAL;
        return EINVAL;
    }

    // Clear the output pointer up front so callers always see nullptr on failure,
    // matching Windows fopen_s semantics.
    *file = nullptr;

    if (filename == nullptr || mode == nullptr)
    {
        errno = EINVAL;
        return EINVAL;
    }

    *file = fopen(filename, mode);

    if (*file != nullptr)
    {
        return 0;
    }

    return errno;
}

int sprintf_s(char* buffer, size_t size_of_buffer, const char* format, ...)
{
    if (buffer == nullptr || size_of_buffer == 0 || format == nullptr)
    {
        if (buffer != nullptr && size_of_buffer > 0)
        {
            buffer[0] = '\0';
        }
        return -1;
    }

    va_list arg_ptr;
    va_start(arg_ptr, format);

    // Use vsnprintf to format the output. It returns the number of characters
    // that would be written (excluding null terminator), even if truncated.
    int ret_val = vsnprintf(buffer, size_of_buffer, format, arg_ptr);
    va_end(arg_ptr);

    // Windows sprintf_s fails on overflow rather than truncating.
    // Detect overflow: ret_val >= size_of_buffer means truncation occurred.
    if (ret_val < 0 || static_cast<size_t>(ret_val) >= size_of_buffer)
    {
        buffer[0] = '\0';
        return -1;
    }

    return ret_val;
}

int fprintf_s(FILE* stream, const char* format, ...)
{
    if (stream == nullptr || format == nullptr)
    {
        return -1;
    }

    int     ret_val;
    va_list arg_ptr;

    va_start(arg_ptr, format);
    ret_val = vfprintf(stream, format, arg_ptr);
    va_end(arg_ptr);
    return ret_val;
}

size_t fread_s(void* buffer, size_t buffer_size, size_t element_size, size_t count, FILE* stream)
{
    if (buffer == nullptr || stream == nullptr)
    {
        errno = EINVAL;
        return 0;
    }

    // Per Windows fread_s, element_size or count of 0 is a no-op, not an error.
    if (element_size == 0 || count == 0)
    {
        return 0;
    }

    // Ensure we don't overflow the buffer.
    size_t max_count = buffer_size / element_size;

    // If the requested element count does not fit in the buffer, fail
    // instead of silently truncating the read, to match Windows fread_s.
    if (count > max_count)
    {
        errno = ERANGE;
        return 0;
    }

    return fread(buffer, element_size, count, stream);
}

int vsnprintf_s(char* buffer, size_t size_of_buffer, size_t count, const char* format, va_list arg_ptr)
{
    if (buffer == nullptr || size_of_buffer == 0 || format == nullptr)
    {
        if (buffer != nullptr && size_of_buffer > 0)
        {
            buffer[0] = '\0';
        }
        return -1;
    }

    // Determine the effective write limit.
    size_t effective_size;
    if (count == _TRUNCATE)
    {
        effective_size = size_of_buffer;
    }
    else if (count < size_of_buffer)
    {
        effective_size = count + 1;
    }
    else
    {
        // count >= size_of_buffer and not _TRUNCATE: error.
        buffer[0] = '\0';
        return -1;
    }

    int result = vsnprintf(buffer, effective_size, format, arg_ptr);

    // vsnprintf returns the number of characters that would have been written.
    // If truncation occurred, ensure null-termination and return -1.
    if (result < 0 || static_cast<size_t>(result) >= effective_size)
    {
        buffer[effective_size - 1] = '\0';
        return -1;
    }

    return result;
}

int sscanf_s(const char* buffer, const char* format, ...)
{
    if (buffer == nullptr || format == nullptr)
    {
        return EOF;
    }

    // Check for unsupported format specifiers that require buffer-size arguments.
    // Windows sscanf_s requires explicit size parameters for %s and %[, but this
    // implementation doesn't validate them. Reject these specifiers to prevent
    // buffer overflow vulnerabilities.
    for (const char* p = format; *p != '\0'; ++p)
    {
        if (*p == '%')
        {
            ++p;
            if (*p == '\0')
                break;

            // Skip flags, width, and length modifiers
            while (*p == '*' || *p == '+' || *p == '-' || *p == ' ' || *p == '#' ||
                   (*p >= '0' && *p <= '9') || *p == 'h' || *p == 'l' || *p == 'L' ||
                   *p == 'j' || *p == 'z' || *p == 't')
            {
                ++p;
                if (*p == '\0')
                    break;
            }

            // Check for unsupported specifiers
            if (*p == 's' || *p == '[')
            {
                errno = EINVAL;
                return EOF;
            }
        }
    }

    int     ret_val;
    va_list arg_ptr;

    va_start(arg_ptr, format);
    ret_val = vsscanf(buffer, format, arg_ptr);
    va_end(arg_ptr);
    return ret_val;
}

#endif  // !_WIN32
