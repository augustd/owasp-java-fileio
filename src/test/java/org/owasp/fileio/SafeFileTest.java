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

import org.owasp.fileio.util.FileTestUtils;
import static org.junit.Assert.*;

import java.io.File;
import java.util.Iterator;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.fileio.util.CollectionsUtil;

public class SafeFileTest {

    private static final Class<?> CLASS = SafeFileTest.class;
    private static final String CLASS_NAME = CLASS.getName();
    
    /**
     * Name of the file in the temporary directory
     */
    private static final String TEST_FILE_NAME = "test.file";
    private static final Set<Character> GOOD_FILE_CHARS = CollectionsUtil.strToUnmodifiableSet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" /* + "." */);
    private static final Set<Character> BAD_FILE_CHARS = CollectionsUtil.strToUnmodifiableSet("\u0000" + /*(File.separatorChar == '/' ? '\\' : '/') +*/ "*|<>?:" /*+ "~!@#$%^&(){}[],`;"*/);
    private File testDir = null;
    private File testFile = null;
    String pathWithNullByte = "/temp/file.txt" + (char) 0;

    @Before
    public void setUp() throws Exception {
	// create a file to test with
	testDir = FileTestUtils.createTmpDirectory(CLASS_NAME).getCanonicalFile();
	testFile = new File(testDir, TEST_FILE_NAME);
	testFile.createNewFile();
	testFile = testFile.getCanonicalFile();
    }

    @After
    public void tearDown() throws Exception {
	FileTestUtils.deleteRecursively(testDir);
    }

    @Test
    public void testEscapeCharactersInFilename() {
	System.out.println("testEscapeCharactersInFilenameInjection");
	File tf = testFile;
	if (tf.exists()) {
	    System.out.println("File is there: " + tf);
	}

	File sf = new File(testDir, "test^.file");
	if (sf.exists()) {
	    System.out.println("  Injection allowed " + sf.getAbsolutePath());
	} else {
	    System.out.println("  Injection didn't work " + sf.getAbsolutePath());
	}
    }

    @Test
    public void testEscapeCharacterInDirectoryInjection() {
	System.out.println("testEscapeCharacterInDirectoryInjection");
	File sf = new File(testDir, "test\\^.^.\\file");
	if (sf.exists()) {
	    System.out.println("  Injection allowed " + sf.getAbsolutePath());
	} else {
	    System.out.println("  Injection didn't work " + sf.getAbsolutePath());
	}
    }

    @Test
    public void testJavaFileInjectionGood() throws ValidationException {
	for (Iterator<Character> i = GOOD_FILE_CHARS.iterator(); i.hasNext();) {
	    String ch = i.next().toString();	// avoids generic issues in 1.4&1.5
	    File sf = new SafeFile(testDir, TEST_FILE_NAME + ch);
	    assertFalse("File \"" + TEST_FILE_NAME + ch + "\" should not exist ((int)ch=" + (int) ch.charAt(0) + ").", sf.exists());
	    sf = new SafeFile(testDir, TEST_FILE_NAME + ch + "test");
	    assertFalse("File \"" + TEST_FILE_NAME + ch + "\" should not exist ((int)ch=" + (int) ch.charAt(0) + ").", sf.exists());
	}
    }

    @Test
    public void testJavaFileInjectionBad() {
	for (Iterator<Character> i = BAD_FILE_CHARS.iterator(); i.hasNext();) {
	    String ch = i.next().toString();	// avoids generic issues in 1.4&1.5
	    try {
		new SafeFile(testDir, TEST_FILE_NAME + ch);
		fail("Able to create SafeFile \"" + TEST_FILE_NAME + ch + "\" ((int)ch=" + (int) ch.charAt(0) + ").");
	    } catch (ValidationException expected) {
	    }
	    try {
		new SafeFile(testDir, TEST_FILE_NAME + ch + "test");
		fail("Able to create SafeFile \"" + TEST_FILE_NAME + ch + "\" ((int)ch=" + (int) ch.charAt(0) + ").");
	    } catch (ValidationException expected) {
	    }
	}
    }

    @Test
    public void testMultipleJavaFileInjectionGood() throws ValidationException {
	for (Iterator<Character> i = GOOD_FILE_CHARS.iterator(); i.hasNext();) {
	    String ch = i.next().toString();	// avoids generic issues in 1.4&1.5
	    ch = ch + ch + ch;
	    File sf = new SafeFile(testDir, TEST_FILE_NAME + ch);
	    assertFalse("File \"" + TEST_FILE_NAME + ch + "\" should not exist ((int)ch=" + (int) ch.charAt(0) + ").", sf.exists());
	    sf = new SafeFile(testDir, TEST_FILE_NAME + ch + "test");
	    assertFalse("File \"" + TEST_FILE_NAME + ch + "\" should not exist ((int)ch=" + (int) ch.charAt(0) + ").", sf.exists());
	}
    }

    @Test
    public void testMultipleJavaFileInjectionBad() {
	for (Iterator<Character> i = BAD_FILE_CHARS.iterator(); i.hasNext();) {
	    String ch = i.next().toString();	// avoids generic issues in 1.4&1.5
	    ch = ch + ch + ch;
	    try {
		new SafeFile(testDir, TEST_FILE_NAME + ch);
		fail("Able to create SafeFile \"" + TEST_FILE_NAME + ch + "\" ((int)ch=" + (int) ch.charAt(0) + ").");
	    } catch (ValidationException expected) {
	    }
	    try {
		new SafeFile(testDir, TEST_FILE_NAME + ch + "test");
		fail("Able to create SafeFile \"" + TEST_FILE_NAME + ch + "\" ((int)ch=" + (int) ch.charAt(0) + ").");
	    } catch (ValidationException expected) {
	    }
	}
    }

    @Test
    public void testAlternateDataStream() {
	try {
	    File sf = new SafeFile(testDir, TEST_FILE_NAME + ":secret.txt");
	    fail("Able to construct SafeFile for alternate data stream: " + sf.getPath());
	} catch (ValidationException expected) {
	}
    }
    
    @Test
    public void testSafeFileWithoutPath() {
        try {
            new SafeFile("hello.txt");
        } catch (ValidationException expected) {
	}
    }

    static public String toHex(final byte b) {
	final char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	final char[] array = {hexDigit[(b >> 4) & 0x0f], hexDigit[b & 0x0f]};
	return new String(array);
    }

    @Test
    public void testCreatePath() throws Exception {
	SafeFile sf = new SafeFile(testFile.getPath());
	assertTrue(sf.exists());
    }

    @Test
    public void testCreateParentPathName() throws Exception {
	SafeFile sf = new SafeFile(testDir, testFile.getName());
	assertTrue(sf.exists());
    }

    @Test
    public void testCreateParentFileName() throws Exception {
	SafeFile sf = new SafeFile(testFile.getParentFile(), testFile.getName());
	assertTrue(sf.exists());
    }

    @Test
    public void testCreateURI() throws Exception {
	SafeFile sf = new SafeFile(testFile.toURI());
	assertTrue(sf.exists());
    }

    @Test
    public void testCreateFileNamePercentNull() {
	try {
	    new SafeFile(testDir + File.separator + "file%00.txt");
	    fail("no exception thrown for file name with percent encoded null");
	} catch (ValidationException expected) {
	}
    }

    @Test
    public void testCreateFileNameQuestion() {
	try {
	    new SafeFile(testFile.getParent() + File.separator + "file?.txt");
	    fail("no exception thrown for file name with question mark in it");
	} catch (ValidationException e) {
	    // expected
	}
    }

    @Test
    public void testCreateFileNameNull() {
	try {
	    new SafeFile(testFile.getParent() + File.separator + "file" + ((char) 0) + ".txt");
	    fail("no exception thrown for file name with null in it");
	} catch (ValidationException e) {
	    // expected
	}
    }

    @Test
    public void testCreateFileHighByte() {
	try {
	    new SafeFile(testFile.getParent() + File.separator + "file" + ((char) 160) + ".txt");
	    fail("no exception thrown for file name with high byte in it");
	} catch (ValidationException e) {
	    // expected
	}
    }

    @Test
    public void testCreateParentPercentNull() {
	try {
	    new SafeFile(testFile.getParent() + File.separator + "file%00.txt");
	    fail("no exception thrown for file name with percent encoded null");
	} catch (ValidationException e) {
	    // expected
	}
    }
}
