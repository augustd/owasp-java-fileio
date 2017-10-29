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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.owasp.fileio.util.NullSafe;
import org.owasp.fileio.util.Utils;

/**
 * A validator performs syntax and possibly semantic validation of a single piece of data from an untrusted source.
 */
public class StringValidationRule {

    protected String typeName;
    protected Encoder encoder;
    protected boolean allowNull = false;
    protected List<Pattern> whitelistPatterns = new ArrayList<Pattern>();
    protected List<Pattern> blacklistPatterns = new ArrayList<Pattern>();
    protected int minLength = 0;
    protected int maxLength = Integer.MAX_VALUE;
    protected boolean validateInputAndCanonical = true;

    public StringValidationRule(String typeName) {
	this.typeName = typeName;
    }

    public StringValidationRule(String typeName, Encoder encoder) {
	this.typeName = typeName;
	this.encoder = encoder;
    }

    public StringValidationRule(String typeName, Encoder encoder, String whitelistPattern) {
	this.typeName = typeName;
	this.encoder = encoder;
	addWhitelistPattern(whitelistPattern);
    }

    /**
     * @param pattern A String which will be compiled into a regular expression pattern to add to the whitelist
     * @throws IllegalArgumentException if pattern is null
     */
    public void addWhitelistPattern(String pattern) {
	if (pattern == null) {
	    throw new IllegalArgumentException("Pattern cannot be null");
	}
	try {
	    whitelistPatterns.add(Pattern.compile(pattern));
	} catch (PatternSyntaxException e) {
	    throw new IllegalArgumentException("Validation misconfiguration, problem with specified pattern: " + pattern, e);
	}
    }

    /**
     * @param p A regular expression pattern to add to the whitelist
     * @throws IllegalArgumentException if p is null
     */
    public void addWhitelistPattern(Pattern p) {
	if (p == null) {
	    throw new IllegalArgumentException("Pattern cannot be null");
	}
	whitelistPatterns.add(p);
    }

    /**
     * @param pattern A String which will be compiled into a regular expression pattern to add to the blacklist

     * @throws IllegalArgumentException if pattern is null
     */
    public void addBlacklistPattern(String pattern) {
	if (pattern == null) {
	    throw new IllegalArgumentException("Pattern cannot be null");
	}
	try {
	    blacklistPatterns.add(Pattern.compile(pattern));
	} catch (PatternSyntaxException e) {
	    throw new IllegalArgumentException("Validation misconfiguration, problem with specified pattern: " + pattern, e);
	}
    }

    /**
     * @param p A regular expression pattern to add to the blacklist
     * @throws IllegalArgumentException if p is null
     */
    public void addBlacklistPattern(Pattern p) {
	if (p == null) {
	    throw new IllegalArgumentException("Pattern cannot be null");
	}
	blacklistPatterns.add(p);
    }

    public void setMinimumLength(int length) {
	minLength = length;
    }

    public void setMaximumLength(int length) {
	maxLength = length;
    }

    /**
     * Set the flag which determines whether the in input itself is checked as well as the canonical form of the input.
     *
     * @param flag The value to set
     */
    public void setValidateInputAndCanonical(boolean flag) {
	validateInputAndCanonical = flag;
    }

    /**
     * checks input against whitelists.
     *
     * @param context The context to include in exception messages
     * @param input the input to check
     * @param orig A original input to include in exception messages. This is not included if it is the same as input.
     * @return input upon a successful check
     * @throws ValidationException if the check fails.
     */
    private String checkWhitelist(String context, String input, String orig) throws ValidationException {
	// check whitelist patterns
	for (Pattern p : whitelistPatterns) {
	    if (!p.matcher(input).matches()) {
		throw new ValidationException(context + ": Invalid input. Please conform to regex " + p.pattern() + (maxLength == Integer.MAX_VALUE ? "" : " with a maximum length of " + maxLength), "Invalid input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input + (NullSafe.equals(orig, input) ? "" : ", orig=" + orig), context);
	    }
	}

	return input;
    }

    /**
     * checks input against whitelists.
     *
     * @param context The context to include in exception messages
     * @param input the input to check
     * @return input upon a successful check
     * @throws ValidationException if the check fails.
     */
    private String checkWhitelist(String context, String input) throws ValidationException {
	return checkWhitelist(context, input, input);
    }

    /**
     * checks input against blacklists.
     *
     * @param context The context to include in exception messages
     * @param input the input to check
     * @param orig A original input to include in exception messages. This is not included if it is the same as input.
     * @return input upon a successful check
     * @throws ValidationException if the check fails.
     */
    private String checkBlacklist(String context, String input, String orig) throws ValidationException {
	// check blacklist patterns
	for (Pattern p : blacklistPatterns) {
	    if (p.matcher(input).matches()) {
		throw new ValidationException(context + ": Invalid input. Dangerous input matching " + p.pattern() + " detected.", "Dangerous input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input + (NullSafe.equals(orig, input) ? "" : ", orig=" + orig), context);
	    }
	}

	return input;
    }

    /**
     * checks input against blacklists.
     *
     * @param context The context to include in exception messages
     * @param input the input to check
     * @return input upon a successful check
     * @throws ValidationException if the check fails.
     */
    private String checkBlacklist(String context, String input) throws ValidationException {
	return checkBlacklist(context, input, input);
    }

    /**
     * checks input lengths
     *
     * @param context The context to include in exception messages
     * @param input the input to check
     * @param orig A origional input to include in exception messages. This is not included if it is the same as input.
     * @return input upon a successful check
     * @throws ValidationException if the check fails.
     */
    private String checkLength(String context, String input, String orig) throws ValidationException {
	if (input.length() < minLength) {
	    throw new ValidationException(context + ": Invalid input. The minimum length of " + minLength + " characters was not met.", "Input does not meet the minimum length of " + minLength + " by " + (minLength - input.length()) + " characters: context=" + context + ", type=" + getTypeName() + "), input=" + input + (NullSafe.equals(input, orig) ? "" : ", orig=" + orig), context);
	}

	if (input.length() > maxLength) {
	    throw new ValidationException(context + ": Invalid input. The maximum length of " + maxLength + " characters was exceeded.", "Input exceeds maximum allowed length of " + maxLength + " by " + (input.length() - maxLength) + " characters: context=" + context + ", type=" + getTypeName() + ", orig=" + orig + ", input=" + input, context);
	}

	return input;
    }

    /**
     * checks input lengths
     *
     * @param context The context to include in exception messages
     * @param input the input to check
     * @return input upon a successful check
     * @throws ValidationException if the check fails.
     */
    private String checkLength(String context, String input) throws ValidationException {
	return checkLength(context, input, input);
    }

    /**
     * checks input emptiness
     *
     * @param context The context to include in exception messages
     * @param input the input to check
     * @param orig A origional input to include in exception messages. This is not included if it is the same as input.
     * @return input upon a successful check
     * @throws ValidationException if the check fails.
     */
    private String checkEmpty(String context, String input, String orig) throws ValidationException {
	if (!Utils.isEmpty(input)) {
	    return input;
	}
	if (allowNull) {
	    return null;
	}
	throw new ValidationException(context + ": Input required.", "Input required: context=" + context + "), input=" + input + (NullSafe.equals(input, orig) ? "" : ", orig=" + orig), context);
    }

    /**
     * checks input emptiness
     *
     * @param context The context to include in exception messages
     * @param input the input to check
     * @return input upon a successful check
     * @throws ValidationException if the check fails.
     */
    private String checkEmpty(String context, String input) throws ValidationException {
	return checkEmpty(context, input, input);
    }

    /**
     * {@inheritDoc}
     */
    public String getValid(String context, String input) throws ValidationException {
	String data = null;

	// checks on input itself

	// check for empty/null
	if (checkEmpty(context, input) == null) {
	    return null;
	}

	if (validateInputAndCanonical) {
	    //first validate pre-canonicalized data

	    // check length
	    checkLength(context, input);

	    // check whitelist patterns
	    checkWhitelist(context, input);

	    // check blacklist patterns
	    checkBlacklist(context, input);

	    // canonicalize
	    data = encoder.canonicalize(input);

	} else {

	    //skip canonicalization
	    data = input;
	}

	// check for empty/null
	if (checkEmpty(context, data, input) == null) {
	    return null;
	}

	// check length
	checkLength(context, data, input);

	// check whitelist patterns
	checkWhitelist(context, data, input);

	// check blacklist patterns
	checkBlacklist(context, data, input);

	// validation passed
	return data;
    }

    public String sanitize(String context, String input) {
	return whitelist(input, Encoder.CHAR_ALPHANUMERICS);
    }

    /**
     * {@inheritDoc}
     */
    public String whitelist(String input, char[] whitelist) {
	Set whiteSet = Utils.arrayToSet(whitelist);
	return whitelist(input, whiteSet);
    }

    /**
     * Removes characters that aren't in the whitelist from the input String. O(input.length) whitelist performance
     *
     * @param input String to be sanitized
     * @param whitelist allowed characters
     * @return input stripped of all chars that aren't in the whitelist
     */
    public String whitelist(String input, Set<Character> whitelist) {
	StringBuilder stripped = new StringBuilder();
	for (int i = 0; i < input.length(); i++) {
	    char c = input.charAt(i);
	    if (whitelist.contains(c)) {
		stripped.append(c);
	    }
	}
	return stripped.toString();
    }

    public String getTypeName() {
	return typeName;
    }

    public Encoder getEncoder() {
	return encoder;
    }

    public boolean isAllowNull() {
	return allowNull;
    }

    public void setAllowNull(boolean allowNull) {
	this.allowNull = allowNull;
    }
}
