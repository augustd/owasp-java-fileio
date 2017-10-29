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
package org.owasp.fileio;

import org.owasp.fileio.util.Utils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.owasp.fileio.codecs.Codec;
import org.owasp.fileio.codecs.HTMLEntityCodec;
import org.owasp.fileio.codecs.PercentCodec;

/**
 * Reference implementation of the Encoder interface. This implementation takes a whitelist approach to encoding, meaning that everything not specifically identified in a list of "immune" characters
 * is encoded.
 */
public class Encoder {

    private static volatile Encoder singletonInstance;
    public final static char[] CHAR_ALPHANUMERICS = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    public static final Set<Character> ALPHANUMERICS;

    static {
	ALPHANUMERICS = Utils.arrayToSet(Encoder.CHAR_ALPHANUMERICS);
    }
    private boolean restrictMultiple = true;
    private boolean restrictMixed = true;

    public boolean isRestrictMultiple() {
	return restrictMultiple;
    }

    public void setRestrictMultiple(boolean restrictMultiple) {
	this.restrictMultiple = restrictMultiple;
    }

    public boolean isRestrictMixed() {
	return restrictMixed;
    }

    public void setRestrictMixed(boolean restrictMixed) {
	this.restrictMixed = restrictMixed;
    }

    public static Encoder getInstance() {
	if (singletonInstance == null) {
	    synchronized (Encoder.class) {
		if (singletonInstance
			== null) {
		    singletonInstance = new Encoder();
		}
	    }
	}
	return singletonInstance;
    }
    // Codecs
    private List codecs = new ArrayList();
    private HTMLEntityCodec htmlCodec = new HTMLEntityCodec();
    private PercentCodec percentCodec = new PercentCodec();

    /**
     * Instantiates a new DefaultEncoder with the default codecs
     */
    public Encoder() {
	codecs.add(htmlCodec);
	codecs.add(percentCodec);
    }

    /**
     * Instantiates a new DefaultEncoder with the default codecs
     * @param codecs A List of Codecs to use
     */
    public Encoder(List<Codec> codecs) {
	this.codecs = codecs;
    }

    /**
     * {@inheritDoc}
     */
    public String canonicalize(String input) {
	if (input == null) {
	    return null;
	}

	// Issue 231 - These are reverse boolean logic in the Encoder interface, so we need to invert these values - CS
	return canonicalize(input, restrictMultiple, restrictMixed);
    }

    /**
     * {@inheritDoc}
     */
    public String canonicalize(String input, boolean strict) {
	return canonicalize(input, strict, strict);
    }

    /**
     * {@inheritDoc}
     */
    public String canonicalize(String input, boolean restrictMultiple, boolean restrictMixed) {
	if (input == null) {
	    return null;
	}

	String working = input;
	Codec codecFound = null;
	int mixedCount = 1;
	int foundCount = 0;
	boolean clean = false;
	while (!clean) {
	    clean = true;

	    // try each codec and keep track of which ones work
	    Iterator i = codecs.iterator();
	    while (i.hasNext()) {
		Codec codec = (Codec) i.next();
		String old = working;
		working = codec.decode(working);
		if (!old.equals(working)) {
		    if (codecFound != null && codecFound != codec) {
			mixedCount++;
		    }
		    codecFound = codec;
		    if (clean) {
			foundCount++;
		    }
		    clean = false;
		}
	    }
	}

	// do strict tests and handle if any mixed, multiple, nested encoding were found
	if (foundCount >= 2 && mixedCount > 1) {
	    if (restrictMultiple || restrictMixed) {
		//TODO: throw new ValidationException("Input validation failure", "Multiple (" + foundCount + "x) and mixed encoding (" + mixedCount + "x) detected in " + input);
	    } else {
		//TODO: logger.warning(Logger.SECURITY_FAILURE, "Multiple (" + foundCount + "x) and mixed encoding (" + mixedCount + "x) detected in " + input);
	    }
	} else if (foundCount >= 2) {
	    if (restrictMultiple) {
		//TODO: throw new ValidationException("Input validation failure", "Multiple (" + foundCount + "x) encoding detected in " + input);
	    } else {
		//TODO: logger.warning(Logger.SECURITY_FAILURE, "Multiple (" + foundCount + "x) encoding detected in " + input);
	    }
	} else if (mixedCount > 1) {
	    if (restrictMixed) {
		//TODO: throw new ValidationException("Input validation failure", "Mixed encoding (" + mixedCount + "x) detected in " + input);
	    } else {
		//TODO: logger.warning(Logger.SECURITY_FAILURE, "Mixed encoding (" + mixedCount + "x) detected in " + input);
	    }
	}
	return working;
    }
}
