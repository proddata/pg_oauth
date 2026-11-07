#include "base64url.h"

static const char base64url_alphabet[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int
base64url_value(unsigned char byte)
{
	if (byte >= 'A' && byte <= 'Z')
		return byte - 'A';
	if (byte >= 'a' && byte <= 'z')
		return byte - 'a' + 26;
	if (byte >= '0' && byte <= '9')
		return byte - '0' + 52;
	if (byte == '-')
		return 62;
	if (byte == '_')
		return 63;
	return -1;
}

bool
pg_oauth_base64url_valid(const char *data, size_t length)
{
	int			last_value;

	if (data == NULL || length == 0 || length % 4 == 1)
		return false;
	for (size_t i = 0; i < length; i++)
	{
		if (base64url_value((unsigned char) data[i]) < 0)
			return false;
	}
	last_value = base64url_value((unsigned char) data[length - 1]);
	if (length % 4 == 2 && (last_value & 0x0f) != 0)
		return false;
	if (length % 4 == 3 && (last_value & 0x03) != 0)
		return false;
	return true;
}

bool
pg_oauth_base64url_decoded_size(size_t encoded_length, size_t maximum,
								size_t *decoded_length)
{
	size_t		length;

	if (decoded_length == NULL)
		return false;
	length = (encoded_length / 4) * 3;
	if (encoded_length % 4 == 2)
		length++;
	else if (encoded_length % 4 == 3)
		length += 2;
	if (length > maximum)
		return false;
	*decoded_length = length;
	return true;
}

bool
pg_oauth_base64url_decode(const char *data, size_t length, uint8_t *decoded,
						  size_t decoded_size)
{
	size_t		input = 0;
	size_t		output = 0;
	size_t		expected;

	if (!pg_oauth_base64url_valid(data, length) || decoded == NULL ||
		!pg_oauth_base64url_decoded_size(length, SIZE_MAX, &expected) ||
		expected != decoded_size)
		return false;
	while (input + 4 <= length)
	{
		uint32_t	bits = ((uint32_t) base64url_value(data[input]) << 18) |
			((uint32_t) base64url_value(data[input + 1]) << 12) |
			((uint32_t) base64url_value(data[input + 2]) << 6) |
			(uint32_t) base64url_value(data[input + 3]);

		decoded[output++] = (uint8_t) (bits >> 16);
		decoded[output++] = (uint8_t) (bits >> 8);
		decoded[output++] = (uint8_t) bits;
		input += 4;
	}
	if (length - input == 2)
	{
		uint32_t	bits = ((uint32_t) base64url_value(data[input]) << 6) |
			(uint32_t) base64url_value(data[input + 1]);

		decoded[output] = (uint8_t) (bits >> 4);
	}
	else if (length - input == 3)
	{
		uint32_t	bits = ((uint32_t) base64url_value(data[input]) << 12) |
			((uint32_t) base64url_value(data[input + 1]) << 6) |
			(uint32_t) base64url_value(data[input + 2]);

		decoded[output++] = (uint8_t) (bits >> 10);
		decoded[output] = (uint8_t) (bits >> 2);
	}
	return true;
}

bool
pg_oauth_base64url_encoded_size(size_t input_length, size_t maximum,
								size_t *encoded_length)
{
	size_t		full_blocks;
	size_t		length;

	if (encoded_length == NULL)
		return false;
	full_blocks = input_length / 3;
	if (full_blocks > SIZE_MAX / 4)
		return false;
	length = full_blocks * 4;
	if (input_length % 3 != 0)
	{
		if (length > SIZE_MAX - (input_length % 3 + 1))
			return false;
		length += input_length % 3 + 1;
	}
	if (length > maximum)
		return false;
	*encoded_length = length;
	return true;
}

bool
pg_oauth_base64url_encode(const uint8_t *data, size_t length, char *encoded,
						  size_t encoded_size)
{
	size_t		expected;
	size_t		input = 0;
	size_t		output = 0;

	if ((data == NULL && length != 0) || encoded == NULL ||
		!pg_oauth_base64url_encoded_size(length, SIZE_MAX, &expected) ||
		expected != encoded_size)
		return false;
	while (input + 3 <= length)
	{
		uint32_t	bits = ((uint32_t) data[input] << 16) |
			((uint32_t) data[input + 1] << 8) | data[input + 2];

		encoded[output++] = base64url_alphabet[(bits >> 18) & 63];
		encoded[output++] = base64url_alphabet[(bits >> 12) & 63];
		encoded[output++] = base64url_alphabet[(bits >> 6) & 63];
		encoded[output++] = base64url_alphabet[bits & 63];
		input += 3;
	}
	if (length - input == 1)
	{
		uint32_t	bits = (uint32_t) data[input] << 4;

		encoded[output++] = base64url_alphabet[(bits >> 6) & 63];
		encoded[output] = base64url_alphabet[bits & 63];
	}
	else if (length - input == 2)
	{
		uint32_t	bits = ((uint32_t) data[input] << 10) |
			((uint32_t) data[input + 1] << 2);

		encoded[output++] = base64url_alphabet[(bits >> 12) & 63];
		encoded[output++] = base64url_alphabet[(bits >> 6) & 63];
		encoded[output] = base64url_alphabet[bits & 63];
	}
	return true;
}
