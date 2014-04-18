/**
 * This file is part of the Open Web Application Security Project (OWASP) Java File IO Security project. For details, please see
 * <a href="https://www.owasp.org/index.php/OWASP_Java_File_I_O_Security_Project">https://www.owasp.org/index.php/OWASP_Java_File_I_O_Security_Project</a>.
 *
 * Copyright (c) 2014 - The OWASP Foundation
 *
 * This API is published by OWASP under the Apache 2.0 license. You should read and accept the LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a> - Original ESAPI author
 * @author August Detlefsen <a href="http://www.codemagi.com">CodeMagi</a> - Java File IO Security Project lead
 * @created 2014
 */
package org.owasp.fileio.codecs;

import java.io.UnsupportedEncodingException;
import java.util.Set;

import org.owasp.fileio.Encoder;

/**
 * Implementation of the Codec interface for percent encoding (aka URL encoding).
 */
public class PercentCodec extends Codec {

    private static final Set<Character> UNENCODED_SET = Encoder.ALPHANUMERICS;

    /**
     * Convinence method to encode a string into UTF-8. This wraps the {@link UnsupportedEncodingException} that {@link String#getBytes(String)} throws in a {@link IllegalStateException} as UTF-8
     * support is required by the Java spec and should never throw this exception.
     *
     * @param str the string to encode
     * @return str encoded in UTF-8 as bytes.
     * @throws IllegalStateException wrapped {@link
     *	UnsupportedEncodingException} if {@link String.getBytes(String)} throws it.
     */
    private static byte[] toUtf8Bytes(String str) {
	try {
	    return str.getBytes("UTF-8");
	} catch (UnsupportedEncodingException e) {
	    throw new IllegalStateException("The Java spec requires UTF-8 support.", e);
	}
    }

    /**
     * Append the two upper case hex characters for a byte.
     *
     * @param sb The string buffer to append to.
     * @param b The byte to hexify
     * @return sb with the hex characters appended.
     */
    // rfc3986 2.1: For consistency, URI producers 
    // should use uppercase hexadecimal digits for all percent-
    // encodings.
    private static StringBuilder appendTwoUpperHex(StringBuilder sb, int b) {
	if (b < Byte.MIN_VALUE || b > Byte.MAX_VALUE) {
	    throw new IllegalArgumentException("b is not a byte (was " + b + ')');
	}
	b &= 0xFF;
	if (b < 0x10) {
	    sb.append('0');
	}
	return sb.append(Integer.toHexString(b).toUpperCase());
    }

    /**
     * Encode a character for URLs
     *
     * @param immune characters not to encode
     * @param c character to encode
     * @return the encoded string representing c
     */
    public String encodeCharacter(char[] immune, Character c) {
	String cStr = String.valueOf(c.charValue());
	byte[] bytes;
	StringBuilder sb;

	if (UNENCODED_SET.contains(c)) {
	    return cStr;
	}

	bytes = toUtf8Bytes(cStr);
	sb = new StringBuilder(bytes.length * 3);
	for (byte b : bytes) {
	    appendTwoUpperHex(sb.append('%'), b);
	}
	return sb.toString();
    }

    /**
     * {@inheritDoc}
     *
     * Formats all are legal both upper/lower case: %hh;
     *
     * @param input encoded character using percent characters (such as URL encoding)
     */
    public Character decodeCharacter(PushbackString input) {
	input.mark();
	Character first = input.next();
	if (first == null) {
	    input.reset();
	    return null;
	}

	// if this is not an encoded character, return null
	if (first != '%') {
	    input.reset();
	    return null;
	}

	// Search for exactly 2 hex digits following
	StringBuilder sb = new StringBuilder();
	for (int i = 0; i < 2; i++) {
	    Character c = input.nextHex();
	    if (c != null) {
		sb.append(c);
	    }
	}
	if (sb.length() == 2) {
	    try {
		// parse the hex digit and create a character
		int i = Integer.parseInt(sb.toString(), 16);
		if (Character.isValidCodePoint(i)) {
		    return (char) i;
		}
	    } catch (NumberFormatException ignored) {
	    }
	}
	input.reset();
	return null;
    }
}
