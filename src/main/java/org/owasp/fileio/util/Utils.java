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
package org.owasp.fileio.util;

import java.util.HashSet;
import java.util.Set;

/**
 * This class provides a number of utility functions.
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class Utils {

    /**
     * Converts an array of chars to a Set of Characters.
     *
     * @param array the contents of the new Set
     * @return a Set containing the elements in the array
     */
    public static Set<Character> arrayToSet(char... array) {
	Set<Character> toReturn;
	if (array == null) {
	    return new HashSet<Character>();
	}
	toReturn = new HashSet<Character>(array.length);
	for (char c : array) {
	    toReturn.add(c);
	}
	return toReturn;
    }

    /**
     * Helper function to check if a String is empty
     *
     * @param input string input value
     * @return boolean response if input is empty or not
     */
    public static boolean isEmpty(String input) {
	return input == null || input.trim().length() == 0;
    }

    /**
     * Helper function to check if a byte array is empty
     *
     * @param input string input value
     * @return boolean response if input is empty or not
     */
    public static boolean isEmpty(byte[] input) {
	return (input == null || input.length == 0);
    }

    /**
     * Helper function to check if a char array is empty
     *
     * @param input string input value
     * @return boolean response if input is empty or not
     */
    public static boolean isEmpty(char[] input) {
	return (input == null || input.length == 0);
    }
}
