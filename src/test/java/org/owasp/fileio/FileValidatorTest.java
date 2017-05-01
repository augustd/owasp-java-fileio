package org.owasp.fileio;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.fail;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import static org.junit.Assert.*;
import org.owasp.fileio.codecs.Codec;
import org.owasp.fileio.codecs.HTMLEntityCodec;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class FileValidatorTest extends TestCase {

    private static final String PREFERRED_ENCODING = "UTF-8";

    public static junit.framework.Test suite() {
	TestSuite suite = new TestSuite(FileValidatorTest.class);
	return suite;
    }

    public void testIsValidFileName() {
	System.out.println("isValidFileName");
	FileValidator instance = new FileValidator();
	assertTrue("Simple valid filename with a valid extension", instance.isValidFileName("test", "aspect.jar", false));
	assertTrue("All valid filename characters are accepted", instance.isValidFileName("test", "!@#$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.jar", false));
	assertTrue("Legal filenames that decode to legal filenames are accepted", instance.isValidFileName("test", "aspe%20ct.jar", false));

	List<ValidationException> errors = new ArrayList<>();
	assertTrue("Simple valid filename with a valid extension", instance.isValidFileName("test", "aspect.jar", false, errors));
	assertTrue("All valid filename characters are accepted", instance.isValidFileName("test", "!@#$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.jar", false, errors));
	assertTrue("Legal filenames that decode to legal filenames are accepted", instance.isValidFileName("test", "aspe%20ct.jar", false, errors));
	assertTrue(errors.isEmpty());
    }

    public void testIsValidFileUpload() throws IOException {
	System.out.println("isValidFileUpload");
	String filepath = new File(System.getProperty("user.dir")).getCanonicalPath();
	String filename = "aspect.jar";
	File parent = new File("/").getCanonicalFile();
	List<ValidationException> errors = new ArrayList<>();
	byte[] content = null;
	try {
	    content = "This is some file content".getBytes(PREFERRED_ENCODING);
	} catch (UnsupportedEncodingException e) {
	    fail(PREFERRED_ENCODING + " not a supported encoding?!?!!!");
	}
	FileValidator instance = new FileValidator();
	try {
	    assertTrue(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, false));
	} catch (ValidationException ve) {
	    //no-op. We want to know about errors!
	}
	assertTrue(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, false, errors));
	assertTrue(errors.size() == 0);

	filepath = "/ridiculous";
	filename = "aspect.jar";
	try {
	    content = "This is some file content".getBytes(PREFERRED_ENCODING);
	} catch (UnsupportedEncodingException e) {
	    fail(PREFERRED_ENCODING + " not a supported encoding?!?!!!");
	}
	try {
	    assertFalse(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, false));
	} catch (ValidationException ve) {
	    //no-op. We want to know about errors!
	}
	assertFalse(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, false, errors));
	assertTrue(errors.size() == 1);
    }

    public void testIsInvalidFilename() {
	System.out.println("testIsInvalidFilename");
	FileValidator instance = new FileValidator();
	char invalidChars[] = "/\\:*?\"<>|".toCharArray();
	for (int i = 0; i < invalidChars.length; i++) {
	    assertFalse(invalidChars[i] + " is an invalid character for a filename",
			instance.isValidFileName("test", "ow" + invalidChars[i] + "asp.jar", false));
	}
	assertFalse("Files must have an extension", instance.isValidFileName("test", "", false));
	assertFalse("Files must have a valid extension", instance.isValidFileName("test.invalidExtension", "", false));
	assertFalse("Filennames cannot be the empty string", instance.isValidFileName("test", "", false));
    }

    public void testIsValidDirectoryPath() throws IOException {
	System.out.println("isValidDirectoryPath");

	// get an encoder with a special list of codecs and make a validator out of it
	List<Codec> list = new ArrayList<Codec>();
	list.add(new HTMLEntityCodec());
	Encoder encoder = new Encoder(list);
	FileValidator instance = new FileValidator(encoder);

	boolean isWindows = (System.getProperty("os.name").indexOf("Windows") != -1) ? true : false;
	File parent = new File("/");

	List<ValidationException> errors = new ArrayList<>();

	if (isWindows) {
	    String sysRoot = new File(System.getenv("SystemRoot")).getCanonicalPath();
	    // Windows paths that don't exist and thus should fail
	    assertFalse(instance.isValidDirectoryPath("test", "c:\\ridiculous", parent, false));
	    assertFalse(instance.isValidDirectoryPath("test", "c:\\jeff", parent, false));
	    assertFalse(instance.isValidDirectoryPath("test", "c:\\temp\\..\\etc", parent, false));

	    // Windows paths
	    assertTrue(instance.isValidDirectoryPath("test", "C:\\", parent, false));                        // Windows root directory
	    assertTrue(instance.isValidDirectoryPath("test", sysRoot, parent, false));                  // Windows always exist directory
	    assertFalse(instance.isValidDirectoryPath("test", sysRoot + "\\System32\\cmd.exe", parent, false));      // Windows command shell

	    // Unix specific paths should not pass
	    assertFalse(instance.isValidDirectoryPath("test", "/tmp", parent, false));      // Unix Temporary directory
	    assertFalse(instance.isValidDirectoryPath("test", "/bin/sh", parent, false));   // Unix Standard shell
	    assertFalse(instance.isValidDirectoryPath("test", "/etc/config", parent, false));

	    // Unix specific paths that should not exist or work
	    assertFalse(instance.isValidDirectoryPath("test", "/etc/ridiculous", parent, false));
	    assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", parent, false));

	    assertFalse(instance.isValidDirectoryPath("test1", "c:\\ridiculous", parent, false, errors));
	    assertTrue(errors.size() == 1);
	    assertFalse(instance.isValidDirectoryPath("test2", "c:\\jeff", parent, false, errors));
	    assertTrue(errors.size() == 2);
	    assertFalse(instance.isValidDirectoryPath("test3", "c:\\temp\\..\\etc", parent, false, errors));
	    assertTrue(errors.size() == 3);

	    // Windows paths
	    assertTrue(instance.isValidDirectoryPath("test4", "C:\\", parent, false, errors));                        // Windows root directory
	    assertTrue(errors.size() == 3);
	    assertTrue(instance.isValidDirectoryPath("test5", sysRoot, parent, false, errors));                  // Windows always exist directory
	    assertTrue(errors.size() == 3);
	    assertFalse(instance.isValidDirectoryPath("test6", sysRoot + "\\System32\\cmd.exe", parent, false, errors));      // Windows command shell
	    assertTrue(errors.size() == 4);

	    // Unix specific paths should not pass
	    assertFalse(instance.isValidDirectoryPath("test7", "/tmp", parent, false, errors));      // Unix Temporary directory
	    assertTrue(errors.size() == 5);
	    assertFalse(instance.isValidDirectoryPath("test8", "/bin/sh", parent, false, errors));   // Unix Standard shell
	    assertTrue(errors.size() == 6);
	    assertFalse(instance.isValidDirectoryPath("test9", "/etc/config", parent, false, errors));
	    assertTrue(errors.size() == 7);

	    // Unix specific paths that should not exist or work
	    assertFalse(instance.isValidDirectoryPath("test10", "/etc/ridiculous", parent, false, errors));
	    assertTrue(errors.size() == 8);
	    assertFalse(instance.isValidDirectoryPath("test11", "/tmp/../etc", parent, false, errors));
	    assertTrue(errors.size() == 9);

	} else {
	    // Windows paths should fail
	    assertFalse(instance.isValidDirectoryPath("test", "c:\\ridiculous", parent, false));
	    assertFalse(instance.isValidDirectoryPath("test", "c:\\temp\\..\\etc", parent, false));

	    // Standard Windows locations should fail
	    assertFalse(instance.isValidDirectoryPath("test", "c:\\", parent, false));                        // Windows root directory
	    assertFalse(instance.isValidDirectoryPath("test", "c:\\Windows\\temp", parent, false));               // Windows temporary directory
	    assertFalse(instance.isValidDirectoryPath("test", "c:\\Windows\\System32\\cmd.exe", parent, false));   // Windows command shell

	    // Unix specific paths should pass
	    assertTrue(instance.isValidDirectoryPath("test", "/", parent, false));         // Root directory
	    assertTrue(instance.isValidDirectoryPath("test", "/bin", parent, false));      // Always exist directory

	    // Unix specific paths that should not exist or work
	    assertFalse(instance.isValidDirectoryPath("test", "/bin/sh", parent, false));   // Standard shell, not dir
	    assertFalse(instance.isValidDirectoryPath("test", "/etc/ridiculous", parent, false));
	    assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", parent, false));

	    // Windows paths should fail
	    assertFalse(instance.isValidDirectoryPath("test1", "c:\\ridiculous", parent, false, errors));
	    assertTrue(errors.size() == 1);
	    assertFalse(instance.isValidDirectoryPath("test2", "c:\\temp\\..\\etc", parent, false, errors));
	    assertTrue(errors.size() == 2);

	    // Standard Windows locations should fail
	    assertFalse(instance.isValidDirectoryPath("test3", "c:\\", parent, false, errors));                        // Windows root directory
	    assertTrue(errors.size() == 3);
	    assertFalse(instance.isValidDirectoryPath("test4", "c:\\Windows\\temp", parent, false, errors));               // Windows temporary directory
	    assertTrue(errors.size() == 4);
	    assertFalse(instance.isValidDirectoryPath("test5", "c:\\Windows\\System32\\cmd.exe", parent, false, errors));   // Windows command shell
	    assertTrue(errors.size() == 5);

	    // Unix specific paths should pass
	    assertTrue(instance.isValidDirectoryPath("test6", "/", parent, false, errors));         // Root directory
	    assertTrue(errors.size() == 5);
	    assertTrue(instance.isValidDirectoryPath("test7", "/bin", parent, false, errors));      // Always exist directory
	    assertTrue(errors.size() == 5);

	    // Unix specific paths that should not exist or work
	    assertFalse(instance.isValidDirectoryPath("test8", "/bin/sh", parent, false, errors));   // Standard shell, not dir
	    assertTrue(errors.size() == 6);
	    assertFalse(instance.isValidDirectoryPath("test9", "/etc/ridiculous", parent, false, errors));
	    assertTrue(errors.size() == 7);
	    assertFalse(instance.isValidDirectoryPath("test10", "/tmp/../etc", parent, false, errors));
	    assertTrue(errors.size() == 8);
	}
    }

    public void TestIsValidDirectoryPath() {
	// isValidDirectoryPath(String, String, boolean)
    }
}